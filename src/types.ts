/** Result of full DCAP quote signature and certificate chain verification. */
export interface DcapVerifyResult {
  /** TCB status: 'UpToDate', 'SWHardeningNeeded', 'OutOfDate', etc. */
  status: string;
  /** Intel security advisory IDs (e.g. 'INTEL-SA-00334') */
  advisoryIds: string[];
}

/**
 * Function that performs full TDX DCAP quote verification.
 * Accepts raw quote bytes and returns verification result.
 * Use `createDcapVerifier()` from `@axlabs/venice-e2ee/dcap` for the default implementation.
 */
export type DcapVerifier = (quoteBytes: Uint8Array) => Promise<DcapVerifyResult>;

export interface VeniceE2EEOptions {
  apiKey: string;
  baseUrl?: string;
  sessionTTL?: number;
  /** Set to false to skip TEE attestation verification. Default: true */
  verifyAttestation?: boolean;
  /**
   * Optional DCAP verifier for full TDX quote signature and cert chain verification.
   * When provided, runs alongside v1 binding checks for complete attestation.
   *
   * ```ts
   * import { createDcapVerifier } from '@axlabs/venice-e2ee/dcap';
   * const e2ee = createVeniceE2EE({ apiKey, dcapVerifier: createDcapVerifier() });
   * ```
   */
  dcapVerifier?: DcapVerifier;
}

export interface E2EESession {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
  pubKeyHex: string;
  modelPubKeyHex: string;
  aesKey: CryptoKey;
  modelId: string;
  created: number;
  /** Attestation verification result (present when verifyAttestation is true) */
  attestation?: import('./attestation.js').AttestationResult;
}

/**
 * OpenAI tool call, either a streaming delta or a completed call on an
 * assistant message. Venice's enclave reads these fields as JSON, so they
 * stay plaintext; they are not part of the encrypted `content` channel.
 */
export interface ToolCall {
  index?: number;
  id?: string;
  type?: string;
  function?: {
    name?: string;
    arguments?: string;
  };
}

/**
 * A chat message passed to `encrypt`.
 *
 * `user` and `system` content must be ciphertext. Assistant and `tool`
 * messages keep `tool_calls`, `tool_call_id`, and `name`. Non-empty `content`
 * is encrypted for every role, including tool-result bodies. `null` stays
 * `null`. An empty string is left empty for every role except `user` and
 * `system` — encrypting it would make the TEE treat a tool-only turn as text.
 */
export interface E2EEMessage {
  role: string;
  content?: string | null;
  name?: string;
  tool_call_id?: string;
  tool_calls?: ToolCall[];
}

/** Message shape sent to Venice after `encrypt`. */
export interface EncryptedMessage {
  role: string;
  content: string | null;
  name?: string;
  tool_call_id?: string;
  tool_calls?: ToolCall[];
}

export interface EncryptedPayload {
  encryptedMessages: EncryptedMessage[];
  headers: Record<string, string>;
  veniceParameters: { enable_e2ee: true };
}

/** One decoded piece of a Venice chat-completions SSE choice, in upstream order. */
export type DecryptedStreamEvent =
  | { kind: 'content'; content: string }
  | { kind: 'tool_calls'; tool_calls: ToolCall[] }
  | { kind: 'finish'; finish_reason: string };
