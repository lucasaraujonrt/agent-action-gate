import { afterEach, beforeAll, describe, expect, spyOn, test } from 'bun:test';
import crypto from 'node:crypto';
import { Database } from 'bun:sqlite';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  ActionGate,
  ApprovalLinks,
  createApprovalHandler,
  hashPin,
  parsePinHash,
  verifyPin,
  type ApprovalLimits,
} from '../src/index';

const PIN = '482913';
const WRONG = '000000';
let pinHash: string;
beforeAll(async () => {
  pinHash = await hashPin(PIN);
});

const cleanup: Array<() => void> = [];
afterEach(() => cleanup.splice(0).forEach((fn) => fn()));

interface Options {
  limits?: Partial<ApprovalLimits>;
  onFile?: boolean;
  gateTtlMs?: number;
  /** Makes the first gate decision throw, as if the process died after the link was consumed. */
  failFirstDecision?: boolean;
}

function scryptCounter() {
  const spy = spyOn(crypto, 'scrypt');
  cleanup.push(() => spy.mockRestore());
  return { get count() { return spy.mock.calls.length; }, reset: () => spy.mockClear() };
}

function rawLinks(path: string) {
  const db = new Database(path);
  cleanup.push(() => db.close());
  return db;
}

const linkRow = (path: string, id: string) =>
  rawLinks(path).query('SELECT status, pin_failures FROM approval_links WHERE action_id=?').get(id) as { status: string; pin_failures: number };

function setup(options: Options = {}) {
  let path = ':memory:';
  let gatePath = ':memory:';
  if (options.onFile) {
    const directory = mkdtempSync(join(tmpdir(), 'approval-link-'));
    cleanup.push(() => rmSync(directory, { recursive: true, force: true }));
    path = join(directory, 'links.db');
    gatePath = join(directory, 'gate.db');
  }
  const gate = new ActionGate(gatePath);
  const clock = { now: Date.now() };
  let failures = options.failFirstDecision ? 1 : 0;
  const decide = <T>(run: () => T): T => {
    if (failures > 0) { failures--; throw new Error('simulated crash'); }
    return run();
  };
  const links = new ApprovalLinks({
    gate: {
      get: (id) => gate.get(id),
      approve: (id, approver, hash) => decide(() => gate.approve(id, approver, hash)),
      reject: (id, approver) => decide(() => gate.reject(id, approver)),
    },
    pinHash,
    path,
    now: () => clock.now,
    limits: options.limits,
  });
  cleanup.push(() => { links.close(); gate.close(); });
  let sequence = 0;
  const prepare = (input: unknown = { text: 'hello' }) =>
    gate.prepare({ actor: 'agent', action: 'send-message', input, idempotencyKey: `call-${++sequence}`, ttlMs: options.gateTtlMs });
  return { gate, links, clock, prepare, gatePath, path };
}

const approvedEvents = (gate: ActionGate, id: string) => gate.history(id).filter((event) => event.kind === 'approved').length;

describe('PIN helpers', () => {
  test('hashPin output verifies the PIN and nothing else', async () => {
    const parsed = parsePinHash(pinHash);
    expect(await verifyPin(PIN, parsed)).toBe(true);
    expect(await verifyPin(WRONG, parsed)).toBe(false);
    expect(await verifyPin(undefined, parsed)).toBe(false);
    expect(await verifyPin('4829130', parsed)).toBe(false);
  });

  test('rejects PINs that are not 6 digits and malformed hashes', async () => {
    await expect(hashPin('12345')).rejects.toThrow();
    await expect(hashPin('12345a')).rejects.toThrow();
    expect(() => parsePinHash('plain-text')).toThrow();
    expect(() => new ApprovalLinks({ gate: new ActionGate(), pinHash: 'scrypt$x$y' })).toThrow();
  });
});

describe('ApprovalLinks token', () => {
  test('a wrong token changes nothing and the right token works once', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);

    for (let i = 0; i < 10; i++) {
      expect(await links.approve(action.id, 'not-the-token', PIN, 'alice')).toEqual({ ok: false, reason: 'invalid_token' });
    }
    expect(gate.get(action.id).status).toBe('pending');

    const first = await links.approve(action.id, token, PIN, 'alice');
    expect(first.ok && first.record.status).toBe('approved');
    expect(first.ok && first.record.approvedBy).toBe('alice');
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'invalid_token' });
    expect(approvedEvents(gate, action.id)).toBe(1);
  });

  test('an unknown action is not found', async () => {
    const { links } = setup();
    expect(await links.approve('missing', 'token', PIN, 'alice')).toEqual({ ok: false, reason: 'not_found' });
    expect(links.view('missing', 'token')).toBeNull();
  });

  test('issue needs a pending action, and re-issuing replaces the old token', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const first = links.issue(action.id);
    const second = links.issue(action.id);
    expect(second.token).not.toBe(first.token);
    expect(await links.approve(action.id, first.token, PIN, 'alice')).toEqual({ ok: false, reason: 'invalid_token' });
    expect((await links.approve(action.id, second.token, PIN, 'alice')).ok).toBe(true);
    expect(() => links.issue(action.id)).toThrow('not pending');
    expect(() => links.issue('missing')).toThrow();
    const rejected = prepare({ other: true });
    gate.reject(rejected.id, 'bob');
    expect(() => links.issue(rejected.id)).toThrow('not pending');
  });

  test('a link expires after its ttl', async () => {
    const { gate, links, clock, prepare } = setup({ limits: { linkTtlMs: 60_000 } });
    const action = prepare();
    const { token, expiresAt } = links.issue(action.id);
    expect(expiresAt).toBe(clock.now + 60_000);
    expect(links.view(action.id, token)).not.toBeNull();

    clock.now += 60_000;
    expect(links.view(action.id, token)).toBeNull();
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'expired' });
    expect(gate.get(action.id).status).toBe('pending');
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'invalid_token' });

    const fresh = links.issue(action.id);
    expect((await links.approve(action.id, fresh.token, PIN, 'alice')).ok).toBe(true);
  });
});

describe('ApprovalLinks issue', () => {
  test('a link never outlives the action it approves', async () => {
    const { gate, links, clock, prepare } = setup({ gateTtlMs: 10 * 60_000 });
    const action = prepare();
    const { token, expiresAt } = links.issue(action.id);
    expect(expiresAt).toBe(action.expiresAt);
    expect(expiresAt).toBeLessThan(clock.now + 72 * 60 * 60_000);

    const shortLived = setup({ gateTtlMs: 10 * 60_000, limits: { linkTtlMs: 60_000 } });
    const other = shortLived.prepare();
    expect(shortLived.links.issue(other.id).expiresAt).toBe(shortLived.clock.now + 60_000);

    clock.now = action.expiresAt;
    expect(links.view(action.id, token)).toBeNull();
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'expired' });
    expect(gate.get(action.id).status).toBe('pending');
  });

  test('issue refuses an action whose own expiry has passed', () => {
    const { links, clock, prepare } = setup({ gateTtlMs: 1000 });
    const action = prepare();
    clock.now = action.expiresAt;
    expect(() => links.issue(action.id)).toThrow('expired');
  });

  test('a locked action cannot get a new link, even while the gate still shows it pending', async () => {
    const { gate, links, prepare } = setup({ limits: { maxPinFailures: 2 }, failFirstDecision: true });
    const action = prepare();
    const { token } = links.issue(action.id);
    await links.approve(action.id, token, WRONG, 'alice');
    expect(await links.approve(action.id, token, WRONG, 'alice')).toEqual({ ok: false, reason: 'pin_lockout' });
    expect(gate.get(action.id).status).toBe('pending');
    expect(() => links.issue(action.id)).toThrow('locked');
  });

  test('re-issuing keeps the wrong-PIN count of the action', async () => {
    const { links, prepare } = setup({ limits: { maxPinFailures: 3 } });
    const action = prepare();
    const first = links.issue(action.id);
    expect(await links.approve(action.id, first.token, WRONG, 'alice')).toMatchObject({ reason: 'wrong_pin', remaining: 2 });
    expect(await links.approve(action.id, first.token, WRONG, 'alice')).toMatchObject({ reason: 'wrong_pin', remaining: 1 });

    const second = links.issue(action.id);
    expect(await links.approve(action.id, second.token, WRONG, 'alice')).toEqual({ ok: false, reason: 'pin_lockout' });
  });

  test('a correct PIN is refunded, so a recovery link keeps the count of wrong PINs only', async () => {
    const { gate, links, prepare } = setup({ failFirstDecision: true });
    const action = prepare();
    const first = links.issue(action.id);
    await links.approve(action.id, first.token, WRONG, 'alice');
    await links.approve(action.id, first.token, WRONG, 'alice');
    expect(await links.approve(action.id, first.token, PIN, 'alice')).toEqual({ ok: false, reason: 'unavailable' });
    expect(gate.get(action.id).status).toBe('pending');

    const recovery = links.issue(action.id);
    expect(await links.approve(action.id, recovery.token, WRONG, 'alice')).toEqual({ ok: false, reason: 'wrong_pin', remaining: 2 });
    expect((await links.approve(action.id, recovery.token, PIN, 'alice')).ok).toBe(true);
  });
});

describe('ApprovalLinks decisions', () => {
  test('two concurrent approvals approve exactly once', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const results = await Promise.all([
      links.approve(action.id, token, PIN, 'alice'),
      links.approve(action.id, token, PIN, 'bob'),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.find((result) => !result.ok)).toEqual({ ok: false, reason: 'invalid_token' });
    expect(approvedEvents(gate, action.id)).toBe(1);
  });

  test('a concurrent approve and reject produce one decision', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const results = await Promise.all([
      links.approve(action.id, token, PIN, 'alice'),
      links.reject(action.id, token, PIN, 'bob'),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    const winner = results.findIndex((result) => result.ok);
    expect(gate.get(action.id).status).toBe(winner === 0 ? 'approved' : 'rejected');
    expect(gate.history(action.id).map((event) => event.kind)).toEqual(['prepared', winner === 0 ? 'approved' : 'rejected']);
  });

  test('reject with the right PIN rejects the action', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const result = await links.reject(action.id, token, PIN, 'alice');
    expect(result.ok && result.record.status).toBe('rejected');
    expect(gate.get(action.id).approvedBy).toBe('alice');
  });

  test('reject needs the PIN too, and wrong PINs on reject lock the link', async () => {
    const { gate, links, prepare } = setup({ limits: { maxPinFailures: 2 } });
    const action = prepare();
    const { token } = links.issue(action.id);
    expect(await links.reject(action.id, token, WRONG, 'mallory')).toEqual({ ok: false, reason: 'wrong_pin', remaining: 1 });
    expect(gate.get(action.id).status).toBe('pending');
    expect(await links.reject(action.id, token, WRONG, 'mallory')).toEqual({ ok: false, reason: 'pin_lockout' });
    expect(gate.get(action.id)).toMatchObject({ status: 'rejected', approvedBy: 'approval-link:pin-lockout' });
    expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(false);
  });

  test('a wrong PIN does not decide and the right PIN does', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    expect(await links.approve(action.id, token, WRONG, 'alice')).toEqual({ ok: false, reason: 'wrong_pin', remaining: 4 });
    expect(await links.approve(action.id, token, undefined, 'alice')).toEqual({ ok: false, reason: 'wrong_pin', remaining: 3 });
    expect(gate.get(action.id).status).toBe('pending');
    expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(true);
  });

  test('the configured number of wrong PINs locks the link and rejects the action', async () => {
    const { gate, links, prepare } = setup({ limits: { maxPinFailures: 3 } });
    const action = prepare();
    const { token } = links.issue(action.id);
    expect(await links.approve(action.id, token, WRONG, 'alice')).toMatchObject({ reason: 'wrong_pin', remaining: 2 });
    expect(await links.approve(action.id, token, WRONG, 'alice')).toMatchObject({ reason: 'wrong_pin', remaining: 1 });
    expect(await links.approve(action.id, token, WRONG, 'alice')).toEqual({ ok: false, reason: 'pin_lockout' });
    expect(gate.get(action.id).status).toBe('rejected');
    expect(links.view(action.id, token)).toBeNull();
    expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(false);
    expect(approvedEvents(gate, action.id)).toBe(0);
  });

  test('there is no option that skips the PIN check', async () => {
    const { gate, prepare, clock } = setup();
    const links = new ApprovalLinks({
      gate, pinHash, now: () => clock.now, verifyPin: async () => true,
    } as ConstructorParameters<typeof ApprovalLinks>[0]);
    cleanup.push(() => links.close());
    const action = prepare();
    const { token } = links.issue(action.id);
    expect(await links.approve(action.id, token, WRONG, 'alice')).toMatchObject({ ok: false, reason: 'wrong_pin' });
    expect(gate.get(action.id).status).toBe('pending');
  });

  test('a right PIN after four wrong ones still works', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    for (let i = 0; i < 4; i++) await links.approve(action.id, token, WRONG, 'alice');
    expect(gate.get(action.id).status).toBe('pending');
    const result = await links.approve(action.id, token, PIN, 'alice');
    expect(result.ok && result.record.status).toBe('approved');
  });

  test('a global lock follows too many wrong PINs across links, then lifts', async () => {
    const { gate, links, clock, prepare } = setup({ limits: { globalFailuresPerHour: 3, globalLockMs: 600_000 } });
    const wrongOn = async () => {
      const action = prepare({ n: Math.random() });
      const { token } = links.issue(action.id);
      return { action, token, result: await links.approve(action.id, token, WRONG, 'alice') };
    };
    for (let i = 0; i < 3; i++) expect((await wrongOn()).result).toMatchObject({ reason: 'wrong_pin' });

    const blocked = prepare({ n: 'blocked' });
    const { token } = links.issue(blocked.id);
    expect(await links.approve(blocked.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'locked' });
    expect(gate.get(blocked.id).status).toBe('pending');

    clock.now += 600_001;
    expect((await links.approve(blocked.id, token, PIN, 'alice')).ok).toBe(true);
  });

  test('a correct PIN does not count toward the global lock', async () => {
    const { links, prepare } = setup({ limits: { globalFailuresPerHour: 2 } });
    for (let i = 0; i < 5; i++) {
      const action = prepare({ n: i });
      const { token } = links.issue(action.id);
      expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(true);
    }
  });

  test('50 parallel wrong-PIN decisions run the PIN check at most maxPinFailures times', async () => {
    const scrypt = scryptCounter();
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    scrypt.reset();
    const results = await Promise.all(Array.from({ length: 50 }, () => links.approve(action.id, token, WRONG, 'alice')));

    expect(scrypt.count).toBe(5);
    expect(results.every((result) => !result.ok)).toBe(true);
    expect(results.filter((result) => !result.ok && result.reason === 'pin_lockout').length).toBeGreaterThanOrEqual(45);
    expect(results.every((result) => !result.ok && ['wrong_pin', 'pin_lockout'].includes(result.reason))).toBe(true);
    expect(gate.get(action.id).status).toBe('rejected');
  });

  test('parallel guesses with a correct PIN among them approve exactly once', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const pins = [WRONG, PIN, PIN, WRONG];
    const results = await Promise.all(pins.map((pin) => links.approve(action.id, token, pin, 'alice')));

    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(gate.get(action.id)).toMatchObject({ status: 'approved', approvedBy: 'alice' });
    expect(approvedEvents(gate, action.id)).toBe(1);
    for (const result of results.filter((result) => !result.ok)) {
      expect(['wrong_pin', 'invalid_token']).toContain(result.ok ? 'ok' : result.reason);
    }
  });

  test('a link left open with its attempts spent is closed and the action rejected', async () => {
    const scrypt = scryptCounter();
    const { gate, links, prepare, path } = setup({ onFile: true });
    const action = prepare();
    const { token } = links.issue(action.id);
    rawLinks(path).prepare('UPDATE approval_links SET pin_failures=5 WHERE action_id=?').run(action.id);
    scrypt.reset();

    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'pin_lockout' });
    expect(scrypt.count).toBe(0);
    expect(gate.get(action.id).status).toBe('rejected');
    expect(linkRow(path, action.id).status).toBe('locked');
    expect(links.view(action.id, token)).toBeNull();
    expect(approvedEvents(gate, action.id)).toBe(0);
    expect(() => links.issue(action.id)).toThrow();
  });

  test('two instances on one database file approve once between them', async () => {
    const { gate, links, prepare, path, gatePath, clock } = setup({ onFile: true });
    const action = prepare();
    const { token } = links.issue(action.id);
    const otherGate = new ActionGate(gatePath);
    const otherLinks = new ApprovalLinks({ gate: otherGate, pinHash, path, now: () => clock.now });
    cleanup.push(() => { otherLinks.close(); otherGate.close(); });

    const results = await Promise.all([
      links.approve(action.id, token, PIN, 'alice'),
      otherLinks.approve(action.id, token, PIN, 'bob'),
    ]);
    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.find((result) => !result.ok)).toEqual({ ok: false, reason: 'invalid_token' });
    expect(approvedEvents(gate, action.id)).toBe(1);
  });
});

describe('ApprovalLinks input binding and reads', () => {
  test('view never changes stored state', async () => {
    const { links, clock, prepare, path } = setup({ onFile: true, limits: { linkTtlMs: 1000 } });
    const action = prepare();
    const { token } = links.issue(action.id);
    const dump = () => {
      const db = new Database(path, { readonly: true });
      try {
        return JSON.stringify([
          db.query('SELECT * FROM approval_links').all(),
          db.query('SELECT * FROM approval_pin_attempts').all(),
          db.query('SELECT * FROM approval_global_lock').all(),
        ]);
      } finally {
        db.close();
      }
    };
    const before = dump();
    for (let i = 0; i < 5; i++) {
      links.view(action.id, token);
      links.view(action.id, 'wrong');
      links.view('missing', token);
    }
    clock.now += 5000;
    expect(links.view(action.id, token)).toBeNull();
    expect(dump()).toBe(before);
  });

  test('a link issued for one input hash cannot approve after the hash differs', async () => {
    const { gate, links, prepare, gatePath } = setup({ onFile: true });
    const action = prepare({ amount: 10 });
    const { token } = links.issue(action.id);
    const tamper = new Database(gatePath);
    tamper.prepare('UPDATE actions SET input_hash=? WHERE id=?').run('f'.repeat(64), action.id);
    tamper.close();

    expect(links.view(action.id, token)).toBeNull();
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'unavailable' });
    expect(gate.get(action.id).status).toBe('pending');
  });

  test('an action decided elsewhere is unavailable through the link', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    gate.reject(action.id, 'bob');
    expect(links.view(action.id, token)).toBeNull();
    expect(await links.approve(action.id, token, PIN, 'alice')).toEqual({ ok: false, reason: 'unavailable' });
  });

  test('link state survives a restart when a path is given', async () => {
    const { gate, links, prepare, path, clock } = setup({ onFile: true });
    const action = prepare();
    const { token } = links.issue(action.id);
    links.close();
    const reopened = new ApprovalLinks({ gate, pinHash, path, now: () => clock.now });
    cleanup.push(() => reopened.close());
    expect((await reopened.approve(action.id, token, PIN, 'alice')).ok).toBe(true);
  });
});

describe('createApprovalHandler', () => {
  const origin = 'http://localhost';
  const post = (path: string, fields: Record<string, string>) =>
    new Request(`${origin}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(fields).toString(),
    });
  const expectSecurityHeaders = (response: Response) => {
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('x-robots-tag')).toContain('noindex');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
  };

  test('GET renders the action with security headers and escapes values', async () => {
    const { links, prepare } = setup();
    const action = prepare({ note: '<img src=x onerror=alert(1)>', quote: '"><script>' });
    const { token } = links.issue(action.id);
    const handler = createApprovalHandler(links);

    const response = await handler(new Request(`${origin}/approve/${action.id}?t=${token}`));
    const html = await response.text();
    expect(response.status).toBe(200);
    expectSecurityHeaders(response);
    expect(html).toContain('send-message');
    expect(html).toContain(action.inputHash);
    expect(html).toContain('name="pin"');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('<script>');
    expect(html).toContain('&#60;img src=x');
  });

  test('a bad token, an unknown action and an unknown path all return the same 404', async () => {
    const { links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const handler = createApprovalHandler(links);
    const bodies = new Set<string>();
    for (const path of [`/approve/${action.id}?t=wrong`, `/approve/${action.id}`, `/approve/missing?t=${token}`, '/other']) {
      const response = await handler(new Request(`${origin}${path}`));
      expect(response.status).toBe(404);
      expectSecurityHeaders(response);
      bodies.add(await response.text());
    }
    expect(bodies.size).toBe(1);
    const badPost = await handler(post(`/approve/${action.id}`, { t: 'wrong', pin: PIN, action: 'approve' }));
    expect(badPost.status).toBe(404);
    expectSecurityHeaders(badPost);
  });

  test('GET never changes the action or the link', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const handler = createApprovalHandler(links);
    for (let i = 0; i < 10; i++) await handler(new Request(`${origin}/approve/${action.id}?t=${token}`));
    expect(gate.get(action.id).status).toBe('pending');
    expect(gate.history(action.id).map((event) => event.kind)).toEqual(['prepared']);
    expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(true);
  });

  test('POST with a wrong PIN re-renders with 401, then the right PIN approves and fires onDecision', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const decisions: string[] = [];
    let decided!: () => void;
    const onDecisionRan = new Promise<void>((resolve) => { decided = resolve; });
    const handler = createApprovalHandler(links, {
      approver: 'phone',
      onDecision: (record, decision) => { decisions.push(`${record.id}:${decision}`); decided(); },
    });
    const path = `/approve/${action.id}`;

    const wrong = await handler(post(path, { t: token, pin: WRONG, action: 'approve' }));
    expect(wrong.status).toBe(401);
    expectSecurityHeaders(wrong);
    expect(await wrong.text()).toContain('4 attempts left');
    expect(gate.get(action.id).status).toBe('pending');

    const right = await handler(post(path, { t: token, pin: PIN, action: 'approve' }));
    expect(right.status).toBe(200);
    expectSecurityHeaders(right);
    expect(gate.get(action.id)).toMatchObject({ status: 'approved', approvedBy: 'phone' });
    await onDecisionRan;
    expect(decisions).toEqual([`${action.id}:approve`]);

    const again = await handler(post(path, { t: token, pin: PIN, action: 'approve' }));
    expect(again.status).toBe(404);
  });

  test('POST reject, invalid action, oversized body and wrong method', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const handler = createApprovalHandler(links);
    const path = `/approve/${action.id}`;

    expect((await handler(post(path, { t: token, pin: PIN, action: 'launch' }))).status).toBe(400);
    const put = await handler(new Request(`${origin}${path}`, { method: 'PUT' }));
    expect(put.status).toBe(405);
    expectSecurityHeaders(put);

    const rejected = await handler(post(path, { t: token, pin: PIN, action: 'reject' }));
    expect(rejected.status).toBe(200);
    expect(gate.get(action.id).status).toBe('rejected');
  });

  test('GET escapes the actor and action names', async () => {
    const { gate, links } = setup();
    const action = gate.prepare({ actor: '<b>agent</b>', action: '"><i>pay</i>', input: { n: 1 }, idempotencyKey: 'escape-1' });
    const { token } = links.issue(action.id);
    const html = await (await createApprovalHandler(links)(new Request(`${origin}/approve/${action.id}?t=${token}`))).text();
    expect(html).not.toContain('<b>agent');
    expect(html).not.toContain('<i>pay');
    expect(html).toContain('&#60;b&#62;agent&#60;/b&#62;');
    expect(html).toContain('&#34;&#62;&#60;i&#62;pay');
  });

  test('an oversized body is refused with 413 and approves nothing', async () => {
    const { gate, links, prepare } = setup();
    const action = prepare();
    const { token } = links.issue(action.id);
    const handler = createApprovalHandler(links);
    const path = `/approve/${action.id}`;
    const valid = new URLSearchParams({ t: token, pin: PIN, action: 'approve' }).toString();

    const declared = await handler(post(path, { t: token, pin: 'x'.repeat(5000), action: 'approve' }));
    expect(declared.status).toBe(413);
    expectSecurityHeaders(declared);

    let pulls = 0;
    const chunk = new TextEncoder().encode('x'.repeat(1000));
    const endless = new ReadableStream<Uint8Array>({
      pull(controller) { pulls++; controller.enqueue(chunk); },
    });
    const chunked = await handler(new Request(`${origin}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: endless,
      duplex: 'half',
    } as RequestInit));
    expect(chunked.status).toBe(413);
    expect(pulls).toBeLessThan(10);

    let bodyPulls = 0;
    const lying = new ReadableStream<Uint8Array>({
      pull(controller) { bodyPulls++; controller.enqueue(new TextEncoder().encode(valid)); controller.close(); },
    });
    const withLength = await handler(new Request(`${origin}${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': '5000' },
      body: lying,
      duplex: 'half',
    } as RequestInit));
    expect(withLength.status).toBe(413);
    expect(bodyPulls).toBe(0);
    expect(gate.get(action.id).status).toBe('pending');
    expect((await links.approve(action.id, token, PIN, 'alice')).ok).toBe(true);
  });

  test('lockout and global lock map to 403 and 429', async () => {
    const { links, prepare } = setup({ limits: { maxPinFailures: 2, globalFailuresPerHour: 3 } });
    const handler = createApprovalHandler(links);
    const first = prepare({ n: 1 });
    const t1 = links.issue(first.id).token;
    await handler(post(`/approve/${first.id}`, { t: t1, pin: WRONG, action: 'approve' }));
    const closed = await handler(post(`/approve/${first.id}`, { t: t1, pin: WRONG, action: 'approve' }));
    expect(closed.status).toBe(403);

    const second = prepare({ n: 2 });
    const t2 = links.issue(second.id).token;
    await handler(post(`/approve/${second.id}`, { t: t2, pin: WRONG, action: 'approve' }));
    const paused = await handler(post(`/approve/${second.id}`, { t: t2, pin: PIN, action: 'approve' }));
    expect(paused.status).toBe(429);
    expectSecurityHeaders(paused);
  });

  test('expired link returns 410 on POST', async () => {
    const { links, clock, prepare } = setup({ limits: { linkTtlMs: 1000 } });
    const action = prepare();
    const { token } = links.issue(action.id);
    clock.now += 1000;
    const handler = createApprovalHandler(links);
    const response = await handler(post(`/approve/${action.id}`, { t: token, pin: PIN, action: 'approve' }));
    expect(response.status).toBe(410);
  });
});
