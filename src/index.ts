import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
  decryptChunk,
  toHex,
} from './crypto.js';
import { decryptSSEStream } from './stream.js';
import {
  verifyAttestation,
  type AttestationResponse,
} from './attestation.js';
import type {
  VeniceE2EEOptions,
  E2EESession,
  E2EEMessage,
  EncryptedMessage,
  EncryptedPayload,
  ToolCall,
  DecryptedStreamEvent,
} from './types.js';

const DEFAULT_BASE_URL = 'https://api.venice.ai';
const DEFAULT_SESSION_TTL = 30 * 60 * 1000; // 30 minutes

/** Venice rejects plaintext `user` and `system` content when E2EE headers are set. */
const CIPHERTEXT_ROLES = new Set(['user', 'system']);

async function encryptOne(msg: E2EEMessage, session: E2EESession): Promise<EncryptedMessage> {
  const encrypted: EncryptedMessage = {
    role: msg.role,
    content: await encryptContent(msg.role, msg.content, session),
  };

  if (typeof msg.name === 'string') encrypted.name = msg.name;
  if (typeof msg.tool_call_id === 'string') encrypted.tool_call_id = msg.tool_call_id;

  const toolCalls = copyToolCalls(msg.tool_calls);
  if (toolCalls) encrypted.tool_calls = toolCalls;

  return encrypted;
}

/**
 * Encrypt a non-empty body for every role so prompts and tool results stay
 * confidential. `null` stays `null`. An empty string is ciphertext only for
 * `user` and `system`; encrypting `""` on an assistant tool call makes the
 * TEE treat that turn as text.
 */
async function encryptContent(
  role: string,
  content: string | null | undefined,
  session: E2EESession
): Promise<string | null> {
  if (typeof content !== 'string') return null;
  if (content.length === 0 && !CIPHERTEXT_ROLES.has(role)) return '';
  return encryptMessage(session.aesKey, session.publicKey, content);
}

function copyToolCalls(toolCalls: ToolCall[] | undefined): ToolCall[] | undefined {
  if (!Array.isArray(toolCalls)) return undefined;
  return toolCalls.map((call) => {
    const copy: ToolCall = {};
    if (typeof call.index === 'number') copy.index = call.index;
    if (typeof call.id === 'string') copy.id = call.id;
    if (typeof call.type === 'string') copy.type = call.type;
    if (call.function) {
      const fn: NonNullable<ToolCall['function']> = {};
      if (typeof call.function.name === 'string') fn.name = call.function.name;
      if (typeof call.function.arguments === 'string') fn.arguments = call.function.arguments;
      copy.function = fn;
    }
    return copy;
  });
}

export function createVeniceE2EE(options: VeniceE2EEOptions) {
  const {
    apiKey,
    baseUrl = DEFAULT_BASE_URL,
    sessionTTL = DEFAULT_SESSION_TTL,
    verifyAttestation: shouldVerify = true,
    dcapVerifier,
  } = options;
  let _session: E2EESession | null = null;
  let _pendingSession: Promise<E2EESession> | null = null;

  async function fetchAttestation(
    modelId: string
  ): Promise<{ response: AttestationResponse; nonceBytes: Uint8Array }> {
    const nonceBytes = crypto.getRandomValues(new Uint8Array(32));
    const nonce = toHex(nonceBytes);
    const url = `${baseUrl}/api/v1/tee/attestation?model=${encodeURIComponent(modelId)}&nonce=${nonce}`;
    const res = await fetch(url, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });
    if (!res.ok) throw new Error(`TEE attestation failed (${res.status})`);
    const response: AttestationResponse = await res.json();
    return { response, nonceBytes };
  }

  async function createSession(modelId: string): Promise<E2EESession> {
    if (
      _session &&
      _session.modelId === modelId &&
      Date.now() - _session.created < sessionTTL
    ) {
      return _session;
    }

    // Deduplicate concurrent calls for the same session
    if (_pendingSession) return _pendingSession;
    _pendingSession = _createSessionInner(modelId);
    try {
      return await _pendingSession;
    } finally {
      _pendingSession = null;
    }
  }

  async function _createSessionInner(modelId: string): Promise<E2EESession> {
    const keypair = generateKeypair();
    const { response, nonceBytes } = await fetchAttestation(modelId);

    const modelPubKeyHex =
      response.signing_key || response.signing_public_key;
    if (!modelPubKeyHex) {
      throw new Error('No signing key in attestation response');
    }

    // Verify attestation if enabled
    let attestation;
    if (shouldVerify) {
      attestation = await verifyAttestation(response, nonceBytes, dcapVerifier);
      if (attestation.errors.length > 0) {
        throw new Error(
          `TEE attestation verification failed:\n  - ${attestation.errors.join('\n  - ')}`
        );
      }
    }

    const aesKey = await deriveAESKey(keypair.privateKey, modelPubKeyHex);

    // Zeroize old session private key before replacing
    if (_session) _session.privateKey.fill(0);

    _session = {
      ...keypair,
      modelPubKeyHex,
      aesKey,
      modelId,
      created: Date.now(),
      attestation,
    };

    return _session;
  }

  async function encrypt(
    messages: E2EEMessage[],
    session: E2EESession
  ): Promise<EncryptedPayload> {
    const encryptedMessages = await Promise.all(
      messages.map((msg) => encryptOne(msg, session))
    );

    return {
      encryptedMessages,
      headers: {
        'X-Venice-TEE-Client-Pub-Key': session.pubKeyHex,
        'X-Venice-TEE-Model-Pub-Key': session.modelPubKeyHex,
        'X-Venice-TEE-Signing-Algo': 'ecdsa',
      },
      veniceParameters: { enable_e2ee: true as const },
    };
  }

  async function decrypt(
    hexChunk: string,
    session: E2EESession
  ): Promise<string> {
    return decryptChunk(session.privateKey, hexChunk);
  }

  async function* decryptStream(
    body: ReadableStream<Uint8Array>,
    session: E2EESession
  ): AsyncGenerator<DecryptedStreamEvent> {
    yield* decryptSSEStream(body, session.privateKey);
  }

  function clearSession(): void {
    if (_session) {
      _session.privateKey.fill(0);
      _session = null;
    }
  }

  return {
    createSession,
    encrypt,
    decryptChunk: decrypt,
    decryptStream,
    clearSession,
  };
}

export function isE2EEModel(modelId: string): boolean {
  return modelId.startsWith('e2ee-');
}

export type {
  VeniceE2EEOptions,
  E2EESession,
  E2EEMessage,
  EncryptedMessage,
  EncryptedPayload,
  ToolCall,
  DecryptedStreamEvent,
  DcapVerifier,
  DcapVerifyResult,
} from './types.js';
export type { AttestationResponse, AttestationResult, ServerVerification } from './attestation.js';
export { verifyAttestation, deriveEthAddress } from './attestation.js';
export {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
  decryptChunk,
  toHex,
  fromHex,
} from './crypto.js';
export { decryptSSEStream } from './stream.js';
