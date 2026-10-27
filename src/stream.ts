import { decryptChunk } from './crypto.js';
import type { DecryptedStreamEvent, ToolCall } from './types.js';

/**
 * Parse an SSE stream from Venice's chat completions endpoint and yield
 * structured events. Text in `delta.content` is decrypted. `delta.tool_calls`
 * and a non-null `finish_reason` are forwarded unchanged — tool-call metadata
 * is plaintext by Venice's E2EE rules.
 *
 * Usage:
 *   for await (const event of decryptSSEStream(response.body, session.privateKey)) {
 *     if (event.kind === 'content') process.stdout.write(event.content);
 *   }
 */
export async function* decryptSSEStream(
  body: ReadableStream<Uint8Array>,
  privateKey: Uint8Array
): AsyncGenerator<DecryptedStreamEvent> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop()!;

      for (const line of lines) {
        const parsed = await parseDataLine(line, privateKey);
        if (parsed.status === 'done') return;
        yield* yieldParsed(parsed);
      }
    }

    if (buffer.trim()) {
      const parsed = await parseDataLine(buffer, privateKey);
      if (parsed.status === 'done') return;
      yield* yieldParsed(parsed);
    }
  } finally {
    reader.releaseLock();
  }
}

interface UpstreamChoice {
  delta?: {
    content?: string | null;
    tool_calls?: ToolCall[];
  };
  finish_reason?: string | null;
}

interface UpstreamEvent {
  choices?: UpstreamChoice[];
}

type ParsedLine =
  | { status: 'ignore' }
  | { status: 'done' }
  | { status: 'events'; events: DecryptedStreamEvent[] };

async function* yieldParsed(parsed: ParsedLine): AsyncGenerator<DecryptedStreamEvent> {
  switch (parsed.status) {
    case 'ignore':
    case 'done':
      return;
    case 'events':
      for (const event of parsed.events) yield event;
      return;
    default: {
      const unexpected: never = parsed;
      throw new Error(`Unhandled SSE parse result: ${JSON.stringify(unexpected)}`);
    }
  }
}

async function parseDataLine(line: string, privateKey: Uint8Array): Promise<ParsedLine> {
  if (!line.startsWith('data: ')) return { status: 'ignore' };
  const data = line.slice(6).trim();
  if (data === '[DONE]') return { status: 'done' };
  if (!data) return { status: 'ignore' };

  let payload: UpstreamEvent;
  try {
    payload = JSON.parse(data) as UpstreamEvent;
  } catch {
    return { status: 'ignore' };
  }

  const events = await eventsFromPayload(payload, privateKey);
  if (events.length === 0) return { status: 'ignore' };
  return { status: 'events', events };
}

async function eventsFromPayload(
  payload: UpstreamEvent,
  privateKey: Uint8Array
): Promise<DecryptedStreamEvent[]> {
  const choice = payload.choices?.[0];
  if (!choice) return [];

  const events: DecryptedStreamEvent[] = [];
  const content = choice.delta?.content;
  if (typeof content === 'string') {
    events.push({ kind: 'content', content: await decryptContent(privateKey, content) });
  }

  const toolCalls = choice.delta?.tool_calls;
  if (Array.isArray(toolCalls) && toolCalls.length > 0) {
    events.push({ kind: 'tool_calls', tool_calls: toolCalls });
  }

  if (typeof choice.finish_reason === 'string' && choice.finish_reason.length > 0) {
    events.push({ kind: 'finish', finish_reason: choice.finish_reason });
  }

  return events;
}

async function decryptContent(privateKey: Uint8Array, content: string): Promise<string> {
  try {
    return await decryptChunk(privateKey, content);
  } catch (e: unknown) {
    if (e instanceof DOMException && e.name === 'OperationError') {
      throw new Error(
        'E2EE decryption failed — session may be stale. Clear the session and retry.'
      );
    }
    throw e;
  }
}
