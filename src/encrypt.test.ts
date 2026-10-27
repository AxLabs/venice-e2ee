import { describe, it, expect } from 'vitest';
import { createVeniceE2EE } from './index.js';
import {
  generateKeypair,
  deriveAESKey,
  fromHex,
  toHex,
} from './crypto.js';
import type { E2EESession } from './types.js';

async function sessionPair(): Promise<{ session: E2EESession; modelPrivateKey: Uint8Array }> {
  const client = generateKeypair();
  const model = generateKeypair();
  const aesKey = await deriveAESKey(client.privateKey, model.pubKeyHex);
  return {
    modelPrivateKey: model.privateKey,
    session: {
      privateKey: client.privateKey,
      publicKey: client.publicKey,
      pubKeyHex: client.pubKeyHex,
      modelPubKeyHex: model.pubKeyHex,
      aesKey,
      modelId: 'e2ee-test',
      created: Date.now(),
    },
  };
}

/** Decrypt a blob produced by encryptMessage, using the TEE model's private key. */
async function decryptWire(cipherHex: string, modelPrivateKey: Uint8Array): Promise<string> {
  const raw = fromHex(cipherHex);
  const clientPubHex = toHex(raw.slice(0, 65));
  const iv = raw.slice(65, 77);
  const ciphertext = raw.slice(77);
  const aesKey = await deriveAESKey(modelPrivateKey, clientPubHex);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext);
  return new TextDecoder().decode(pt);
}

describe('encrypt tool messages', () => {
  it('keeps assistant tool calls and leaves null content null', async () => {
    const { session } = await sessionPair();
    const e2ee = createVeniceE2EE({ apiKey: 'test', verifyAttestation: false });
    const toolCalls = [
      {
        id: 'call_weather',
        type: 'function',
        function: { name: 'get_weather', arguments: '{"city":"Paris"}' },
      },
    ];

    const { encryptedMessages } = await e2ee.encrypt(
      [
        {
          role: 'assistant',
          content: null,
          tool_calls: toolCalls,
        },
      ],
      session
    );

    expect(encryptedMessages).toEqual([
      {
        role: 'assistant',
        content: null,
        tool_calls: toolCalls,
      },
    ]);
  });

  it('does not encrypt an empty assistant body into ciphertext', async () => {
    const { session } = await sessionPair();
    const e2ee = createVeniceE2EE({ apiKey: 'test', verifyAttestation: false });

    const { encryptedMessages } = await e2ee.encrypt(
      [
        {
          role: 'assistant',
          content: '',
          tool_calls: [
            {
              id: 'call_1',
              type: 'function',
              function: { name: 'lookup', arguments: '{}' },
            },
          ],
        },
      ],
      session
    );

    expect(encryptedMessages[0].content).toBe('');
    expect(encryptedMessages[0].tool_calls?.[0].function?.name).toBe('lookup');
  });

  it('encrypts tool-result content and keeps the call id and name', async () => {
    const { session, modelPrivateKey } = await sessionPair();
    const e2ee = createVeniceE2EE({ apiKey: 'test', verifyAttestation: false });
    const secret = '22C and sunny in Paris';

    const { encryptedMessages } = await e2ee.encrypt(
      [
        {
          role: 'tool',
          name: 'get_weather',
          tool_call_id: 'call_weather',
          content: secret,
        },
      ],
      session
    );

    const message = encryptedMessages[0];
    expect(message.role).toBe('tool');
    expect(message.name).toBe('get_weather');
    expect(message.tool_call_id).toBe('call_weather');
    expect(message.content).not.toBe(secret);
    expect(message.content).toMatch(/^[0-9a-f]+$/i);
    expect(await decryptWire(message.content!, modelPrivateKey)).toBe(secret);
  });

  it('encrypts non-empty assistant text and user prompts', async () => {
    const { session, modelPrivateKey } = await sessionPair();
    const e2ee = createVeniceE2EE({ apiKey: 'test', verifyAttestation: false });

    const { encryptedMessages } = await e2ee.encrypt(
      [
        { role: 'system', content: 'be helpful' },
        { role: 'user', content: 'what is the weather?' },
        { role: 'assistant', content: 'I will check.' },
        { role: 'user', content: '' },
      ],
      session
    );

    expect(await decryptWire(encryptedMessages[0].content!, modelPrivateKey)).toBe('be helpful');
    expect(await decryptWire(encryptedMessages[1].content!, modelPrivateKey)).toBe(
      'what is the weather?'
    );
    expect(await decryptWire(encryptedMessages[2].content!, modelPrivateKey)).toBe('I will check.');
    // user/system must still be ciphertext even when the body is empty
    expect(encryptedMessages[3].content).toMatch(/^[0-9a-f]+$/i);
    expect(await decryptWire(encryptedMessages[3].content!, modelPrivateKey)).toBe('');
  });
});
