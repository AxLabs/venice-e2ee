import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  deriveAESKey,
  encryptMessage,
} from './crypto.js';
import { decryptSSEStream } from './stream.js';
import type { DecryptedStreamEvent } from './types.js';

async function collectEvents(
  stream: ReadableStream<Uint8Array>,
  privateKey: Uint8Array
): Promise<DecryptedStreamEvent[]> {
  const events: DecryptedStreamEvent[] = [];
  for await (const event of decryptSSEStream(stream, privateKey)) {
    events.push(event);
  }
  return events;
}

function createSSEStream(events: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const sseText = events.map((e) => `data: ${e}\n\n`).join('');
  return new ReadableStream({
    start(controller) {
      controller.enqueue(encoder.encode(sseText));
      controller.close();
    },
  });
}

function createChunkedSSEStream(events: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const sseText = events.map((e) => `data: ${e}\n\n`).join('');
  // Split into small chunks to simulate real streaming
  const bytes = encoder.encode(sseText);
  const chunkSize = 20;
  return new ReadableStream({
    start(controller) {
      for (let i = 0; i < bytes.length; i += chunkSize) {
        controller.enqueue(bytes.slice(i, i + chunkSize));
      }
      controller.close();
    },
  });
}

async function encryptForStream(
  plaintext: string,
  serverPrivateKey: Uint8Array,
  clientPubKeyHex: string
): Promise<string> {
  const serverEphemeral = generateKeypair();
  const aesKey = await deriveAESKey(serverEphemeral.privateKey, clientPubKeyHex);
  return encryptMessage(aesKey, serverEphemeral.publicKey, plaintext);
}

describe('decryptSSEStream', () => {
  it('decrypts a single-chunk stream', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('Hello!', client.privateKey, client.pubKeyHex);

    // Wait — encryptForStream uses a server ephemeral key and client pub key.
    // decryptSSEStream uses client private key to decrypt.
    // The cipher was created with ECDH(server_eph_priv, client_pub), embedded server_eph_pub.
    // decryptChunk does ECDH(client_priv, server_eph_pub) — same shared secret. ✓

    const sseEvent = JSON.stringify({
      choices: [{ delta: { content: cipherHex } }],
    });

    const stream = createSSEStream([sseEvent, '[DONE]']);
    const events = await collectEvents(stream, client.privateKey);

    expect(events).toEqual([{ kind: 'content', content: 'Hello!' }]);
  });

  it('decrypts multiple chunks with per-chunk ephemeral keys', async () => {
    const client = generateKeypair();
    const plaintexts = ['The ', 'answer ', 'is ', '42.'];

    const events: string[] = [];
    for (const pt of plaintexts) {
      const cipherHex = await encryptForStream(pt, client.privateKey, client.pubKeyHex);
      events.push(
        JSON.stringify({ choices: [{ delta: { content: cipherHex } }] })
      );
    }
    events.push('[DONE]');

    const stream = createSSEStream(events);
    const decoded = await collectEvents(stream, client.privateKey);

    expect(decoded).toEqual(plaintexts.map((content) => ({ kind: 'content', content })));
  });

  it('handles chunked delivery (split across reads)', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('streamed', client.privateKey, client.pubKeyHex);

    const events = [
      JSON.stringify({ choices: [{ delta: { content: cipherHex } }] }),
      '[DONE]',
    ];

    const stream = createChunkedSSEStream(events);
    const decoded = await collectEvents(stream, client.privateKey);

    expect(decoded).toEqual([{ kind: 'content', content: 'streamed' }]);
  });

  it('passes through plaintext content (whitespace tokens)', async () => {
    const client = generateKeypair();

    const events = [
      JSON.stringify({ choices: [{ delta: { content: ' ' } }] }),
      JSON.stringify({ choices: [{ delta: { content: '\n' } }] }),
      '[DONE]',
    ];

    const stream = createSSEStream(events);
    const decoded = await collectEvents(stream, client.privateKey);

    expect(decoded).toEqual([
      { kind: 'content', content: ' ' },
      { kind: 'content', content: '\n' },
    ]);
  });

  it('skips events without content', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('data', client.privateKey, client.pubKeyHex);

    const events = [
      JSON.stringify({ choices: [{ delta: {} }] }),
      JSON.stringify({ choices: [{ delta: { content: cipherHex } }] }),
      JSON.stringify({ choices: [] }),
      '[DONE]',
    ];

    const stream = createSSEStream(events);
    const decoded = await collectEvents(stream, client.privateKey);

    expect(decoded).toEqual([{ kind: 'content', content: 'data' }]);
  });

  it('handles empty stream', async () => {
    const client = generateKeypair();
    const stream = createSSEStream(['[DONE]']);
    const decoded = await collectEvents(stream, client.privateKey);
    expect(decoded).toEqual([]);
  });

  it('yields tool-call deltas unchanged, then the finish reason', async () => {
    const client = generateKeypair();
    const cipherHex = await encryptForStream('Checking.', client.privateKey, client.pubKeyHex);
    const firstCall = {
      index: 0,
      id: 'call_weather',
      type: 'function',
      function: { name: 'get_weather', arguments: '' },
    };
    const argumentDelta = {
      index: 0,
      function: { arguments: '{"city":"Paris"}' },
    };

    const events = [
      JSON.stringify({
        choices: [{ delta: { content: cipherHex }, finish_reason: null }],
      }),
      JSON.stringify({
        choices: [{ delta: { tool_calls: [firstCall] }, finish_reason: null }],
      }),
      JSON.stringify({
        choices: [{ delta: { tool_calls: [argumentDelta] }, finish_reason: null }],
      }),
      JSON.stringify({
        choices: [{ delta: {}, finish_reason: 'tool_calls' }],
      }),
      '[DONE]',
    ];

    const decoded = await collectEvents(createSSEStream(events), client.privateKey);

    expect(decoded).toEqual([
      { kind: 'content', content: 'Checking.' },
      { kind: 'tool_calls', tool_calls: [firstCall] },
      { kind: 'tool_calls', tool_calls: [argumentDelta] },
      { kind: 'finish', finish_reason: 'tool_calls' },
    ]);
  });

  it('keeps content, tool calls, and finish_reason from one SSE event in that order', async () => {
    const client = generateKeypair();
    const call = {
      index: 0,
      id: 'call_1',
      type: 'function',
      function: { name: 'lookup', arguments: '{}' },
    };
    const sseEvent = JSON.stringify({
      choices: [
        {
          delta: { content: ' ', tool_calls: [call] },
          finish_reason: 'length',
        },
      ],
    });

    const decoded = await collectEvents(createSSEStream([sseEvent, '[DONE]']), client.privateKey);

    expect(decoded).toEqual([
      { kind: 'content', content: ' ' },
      { kind: 'tool_calls', tool_calls: [call] },
      { kind: 'finish', finish_reason: 'length' },
    ]);
  });

  it('does not treat a null finish_reason as a terminal event', async () => {
    const client = generateKeypair();
    const events = [
      JSON.stringify({ choices: [{ delta: {}, finish_reason: null }] }),
      JSON.stringify({ choices: [{ finish_reason: 'stop' }] }),
      '[DONE]',
    ];

    const decoded = await collectEvents(createSSEStream(events), client.privateKey);
    expect(decoded).toEqual([{ kind: 'finish', finish_reason: 'stop' }]);
  });
});
