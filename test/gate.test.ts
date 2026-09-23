import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ActionGate } from '../src/index';

const gates: ActionGate[] = [];
const directories: string[] = [];
const gate = () => {
  const instance = new ActionGate();
  gates.push(instance);
  return instance;
};
afterEach(() => {
  gates.splice(0).forEach((instance) => instance.close());
  directories.splice(0).forEach((path) => rmSync(path, { recursive: true, force: true }));
});

describe('ActionGate', () => {
  test('requires the approved input hash and executes once', async () => {
    const actions = gate();
    const prepared = actions.prepare({ actor: 'agent-1', action: 'send-message', input: { text: 'hello' }, idempotencyKey: 'call-1' });
    expect(() => actions.approve(prepared.id, 'reviewer', 'wrong')).toThrow();
    actions.approve(prepared.id, 'reviewer', prepared.inputHash);
    let calls = 0;
    const result = await actions.execute<{ text: string }, string>(prepared.id, async (input) => {
      calls++;
      return input.text;
    });
    expect(result.status).toBe('succeeded');
    expect(result.result).toBe('hello');
    await expect(actions.execute(prepared.id, async () => calls++)).rejects.toThrow();
    expect(calls).toBe(1);
    expect(actions.history(prepared.id).map((event) => event.kind)).toEqual(['prepared', 'approved', 'executing', 'succeeded']);
  });

  test('deduplicates prepare and rejects changed input', () => {
    const actions = gate();
    const request = { actor: 'agent', action: 'update', input: { b: 2, a: 1 }, idempotencyKey: 'key' };
    const first = actions.prepare(request);
    expect(actions.prepare({ ...request, input: { a: 1, b: 2 } }).id).toBe(first.id);
    expect(() => actions.prepare({ ...request, input: { a: 3 } })).toThrow('different input');
  });

  test('keeps an uncertain external call from being retried', async () => {
    const actions = gate();
    const prepared = actions.prepare({ actor: 'agent', action: 'publish', input: { id: 1 }, idempotencyKey: 'publish-1' });
    actions.approve(prepared.id, 'reviewer', prepared.inputHash);
    const result = await actions.execute(prepared.id, async () => { throw new Error('network timeout'); });
    expect(result.status).toBe('uncertain');
    expect(result.error).toBe('network timeout');
    await expect(actions.execute(prepared.id, async () => 'duplicate')).rejects.toThrow();
    expect(actions.reconcile(prepared.id, { status: 'succeeded', result: { providerId: 'p1' } }).result).toEqual({ providerId: 'p1' });
  });

  test('persists the approval and audit trail across a restart', () => {
    const directory = mkdtempSync(join(tmpdir(), 'action-gate-'));
    directories.push(directory);
    const path = join(directory, 'gate.db');
    const first = new ActionGate(path);
    const prepared = first.prepare({ actor: 'agent', action: 'update', input: { id: 1 }, idempotencyKey: 'restart-1' });
    first.approve(prepared.id, 'reviewer', prepared.inputHash);
    first.close();
    const second = new ActionGate(path);
    gates.push(second);
    expect(second.get(prepared.id).status).toBe('approved');
    expect(second.history(prepared.id).map((event) => event.kind)).toEqual(['prepared', 'approved']);
  });
});
