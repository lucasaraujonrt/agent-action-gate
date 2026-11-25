import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Database } from 'bun:sqlite';
import type { ActionGate, ActionRecord } from './index';

const PIN_FORMAT = /^\d{6}$/;
const KEY_LENGTH = 32;
const HOUR_MS = 60 * 60_000;

export interface ParsedPinHash {
  salt: Buffer;
  hash: Buffer;
}

function derive(pin: string, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(pin, salt, KEY_LENGTH, (error, key) => (error ? reject(error) : resolve(key)));
  });
}

/** Returns `scrypt$<salt base64>$<hash base64>`. Store this string, never the PIN. */
export async function hashPin(pin: string): Promise<string> {
  if (!PIN_FORMAT.test(pin)) throw new Error('PIN must be exactly 6 digits');
  const salt = randomBytes(16);
  return `scrypt$${salt.toString('base64')}$${(await derive(pin, salt)).toString('base64')}`;
}

export function parsePinHash(raw: string): ParsedPinHash {
  const [scheme, salt, hash] = raw.split('$');
  const parsed = { salt: Buffer.from(salt ?? '', 'base64'), hash: Buffer.from(hash ?? '', 'base64') };
  if (scheme !== 'scrypt' || parsed.salt.length < 16 || parsed.hash.length !== KEY_LENGTH) {
    throw new Error('PIN hash must look like scrypt$<salt base64>$<hash base64>');
  }
  return parsed;
}

/** Always runs scrypt, even for malformed input, so timing does not reveal the format check. */
export async function verifyPin(pin: string | undefined, stored: ParsedPinHash): Promise<boolean> {
  const given = typeof pin === 'string' ? pin : '';
  const key = await derive(given, stored.salt);
  return timingSafeEqual(key, stored.hash) && PIN_FORMAT.test(given);
}

export type LinkStatus = 'open' | 'used' | 'locked' | 'expired';

export interface ApprovalLimits {
  linkTtlMs: number;
  maxPinFailures: number;
  globalFailuresPerHour: number;
  globalLockMs: number;
}

export interface ApprovalLinksOptions {
  gate: Pick<ActionGate, 'get' | 'approve' | 'reject'>;
  /** Output of `hashPin`. */
  pinHash: string;
  /** SQLite file for link state. Defaults to `:memory:`, which loses links on restart. */
  path?: string;
  now?: () => number;
  limits?: Partial<ApprovalLimits>;
  /** Replaces the scrypt check. Meant for tests that count or stub PIN verification. */
  verifyPin?: (pin: string | undefined, stored: ParsedPinHash) => Promise<boolean>;
}

type Failure = 'not_found' | 'invalid_token' | 'expired' | 'pin_lockout' | 'locked' | 'unavailable';

export type ApprovalResult =
  | { ok: true; record: ActionRecord }
  | { ok: false; reason: Failure }
  | { ok: false; reason: 'wrong_pin'; remaining: number };

interface LinkRow {
  action_id: string;
  token_hash: string | null;
  input_hash: string;
  expires_at: number;
  pin_failures: number;
  status: LinkStatus;
}

type Reservation = { ok: true; attemptId: number; inputHash: string } | { ok: false; reason: Failure };

const DEFAULT_LIMITS: ApprovalLimits = {
  linkTtlMs: 72 * HOUR_MS,
  maxPinFailures: 5,
  globalFailuresPerHour: 20,
  globalLockMs: HOUR_MS,
};

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function sameHash(a: string | null, b: string): boolean {
  return a !== null && timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

export class ApprovalLinks {
  private readonly db: Database;
  private readonly gate: ApprovalLinksOptions['gate'];
  private readonly pin: ParsedPinHash;
  private readonly now: () => number;
  private readonly limits: ApprovalLimits;
  private readonly verify: NonNullable<ApprovalLinksOptions['verifyPin']>;

  constructor(options: ApprovalLinksOptions) {
    const path = options.path ?? ':memory:';
    this.gate = options.gate;
    this.pin = parsePinHash(options.pinHash);
    this.now = options.now ?? Date.now;
    this.limits = { ...DEFAULT_LIMITS, ...options.limits };
    this.verify = options.verifyPin ?? verifyPin;
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path, { create: true });
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approval_links (
        action_id TEXT PRIMARY KEY,
        token_hash TEXT,
        input_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        pin_failures INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL CHECK (status IN ('open','used','locked','expired'))
      );
      CREATE TABLE IF NOT EXISTS approval_pin_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approval_global_lock (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        locked_until INTEGER NOT NULL
      );
    `);
  }

  issue(actionId: string): { token: string; expiresAt: number } {
    const record = this.gate.get(actionId);
    if (record.status !== 'pending') throw new Error('action is not pending');
    const token = randomBytes(32).toString('base64url');
    const expiresAt = this.now() + this.limits.linkTtlMs;
    this.db.prepare(`
      INSERT INTO approval_links (action_id, token_hash, input_hash, expires_at, pin_failures, status)
      VALUES (?, ?, ?, ?, 0, 'open')
      ON CONFLICT(action_id) DO UPDATE SET
        token_hash=excluded.token_hash, input_hash=excluded.input_hash, expires_at=excluded.expires_at,
        pin_failures=0, status='open'
    `).run(actionId, sha256(token), record.inputHash, expiresAt);
    return { token, expiresAt };
  }

  /** Read-only. Returns the action when the link could still be used right now. */
  view(actionId: string, token: string | undefined): ActionRecord | null {
    const row = this.row(actionId);
    if (!row || !token || row.status !== 'open' || !sameHash(row.token_hash, sha256(token))) return null;
    if (row.expires_at <= this.now()) return null;
    try {
      const record = this.gate.get(actionId);
      return record.status === 'pending' && record.inputHash === row.input_hash ? record : null;
    } catch {
      return null;
    }
  }

  approve(actionId: string, token: string | undefined, pin: string | undefined, approver: string): Promise<ApprovalResult> {
    return this.decide(actionId, token, pin, (inputHash) => this.gate.approve(actionId, approver, inputHash));
  }

  reject(actionId: string, token: string | undefined, pin: string | undefined, approver: string): Promise<ApprovalResult> {
    return this.decide(actionId, token, pin, () => this.gate.reject(actionId, approver));
  }

  close(): void {
    this.db.close();
  }

  /**
   * A PIN attempt is reserved in the same transaction that checks the token, so N parallel
   * requests cannot all reach scrypt: at most `maxPinFailures` do. A correct PIN refunds it.
   */
  private async decide(
    actionId: string,
    token: string | undefined,
    pin: string | undefined,
    decideInGate: (inputHash: string) => ActionRecord,
  ): Promise<ApprovalResult> {
    const tokenHash = sha256(token ?? '');
    const reservation = this.reserve(actionId, tokenHash);
    if (!reservation.ok) return reservation;

    if (!(await this.verify(pin, this.pin))) return this.wrongPin(actionId, tokenHash);

    const consumed = this.consume(actionId, tokenHash, reservation.attemptId);
    if (consumed !== 'ok') return { ok: false, reason: consumed };
    try {
      return { ok: true, record: decideInGate(reservation.inputHash) };
    } catch {
      return { ok: false, reason: 'unavailable' };
    }
  }

  private reserve(actionId: string, tokenHash: string): Reservation {
    return this.db.transaction((): Reservation => {
      const now = this.now();
      const row = this.row(actionId);
      if (!row) return { ok: false, reason: 'not_found' };
      if (row.status !== 'open' || !sameHash(row.token_hash, tokenHash)) return { ok: false, reason: 'invalid_token' };
      if (row.expires_at <= now) {
        this.db.prepare("UPDATE approval_links SET status='expired', token_hash=NULL WHERE action_id=? AND status='open'").run(actionId);
        return { ok: false, reason: 'expired' };
      }
      this.db.prepare('DELETE FROM approval_pin_attempts WHERE at<=?').run(now - HOUR_MS);
      if (this.lockedUntil() > now || this.recentAttempts() >= this.limits.globalFailuresPerHour) {
        return { ok: false, reason: 'locked' };
      }
      const reserved = this.db.prepare(`
        UPDATE approval_links SET pin_failures=pin_failures+1
        WHERE action_id=? AND token_hash=? AND status='open' AND pin_failures<?
      `).run(actionId, tokenHash, this.limits.maxPinFailures).changes;
      if (reserved !== 1) return { ok: false, reason: 'pin_lockout' };
      const attempt = this.db.prepare('INSERT INTO approval_pin_attempts (at) VALUES (?)').run(now);
      return { ok: true, attemptId: Number(attempt.lastInsertRowid), inputHash: row.input_hash };
    }).immediate();
  }

  private consume(actionId: string, tokenHash: string, attemptId: number): 'ok' | 'invalid_token' | 'expired' {
    return this.db.transaction((): 'ok' | 'invalid_token' | 'expired' => {
      this.db.prepare('DELETE FROM approval_pin_attempts WHERE id=?').run(attemptId);
      const used = this.db.prepare(`
        UPDATE approval_links SET status='used', token_hash=NULL, pin_failures=MAX(pin_failures-1, 0)
        WHERE action_id=? AND token_hash=? AND status='open' AND expires_at>?
      `).run(actionId, tokenHash, this.now()).changes;
      if (used === 1) return 'ok';
      const row = this.row(actionId);
      return row?.status === 'open' && sameHash(row.token_hash, tokenHash) ? 'expired' : 'invalid_token';
    }).immediate();
  }

  private wrongPin(actionId: string, tokenHash: string): ApprovalResult {
    const outcome = this.db.transaction((): ApprovalResult & { closed?: true } => {
      const now = this.now();
      if (this.recentAttempts() >= this.limits.globalFailuresPerHour && this.lockedUntil() <= now) {
        this.db.prepare(`
          INSERT INTO approval_global_lock (id, locked_until) VALUES (1, ?)
          ON CONFLICT(id) DO UPDATE SET locked_until=excluded.locked_until
        `).run(now + this.limits.globalLockMs);
        this.db.exec('DELETE FROM approval_pin_attempts');
      }
      const row = this.row(actionId);
      if (!row) return { ok: false, reason: 'not_found' };
      if (row.status === 'locked') return { ok: false, reason: 'pin_lockout' };
      if (row.status !== 'open' || !sameHash(row.token_hash, tokenHash)) return { ok: false, reason: 'invalid_token' };
      if (row.pin_failures < this.limits.maxPinFailures) {
        return { ok: false, reason: 'wrong_pin', remaining: this.limits.maxPinFailures - row.pin_failures };
      }
      this.db.prepare("UPDATE approval_links SET status='locked', token_hash=NULL WHERE action_id=?").run(actionId);
      return { ok: false, reason: 'pin_lockout', closed: true };
    }).immediate();
    if (!('closed' in outcome)) return outcome;
    try {
      this.gate.reject(actionId, 'approval-link:pin-lockout');
    } catch {
      // The action was decided another way in the meantime; the link is closed either way.
    }
    return { ok: false, reason: 'pin_lockout' };
  }

  private row(actionId: string): LinkRow | null {
    return this.db.prepare('SELECT * FROM approval_links WHERE action_id=?').get(actionId) as LinkRow | null;
  }

  private lockedUntil(): number {
    const row = this.db.prepare('SELECT locked_until FROM approval_global_lock WHERE id=1').get() as { locked_until: number } | null;
    return row?.locked_until ?? 0;
  }

  private recentAttempts(): number {
    const row = this.db.prepare('SELECT COUNT(*) AS n FROM approval_pin_attempts').get() as { n: number };
    return row.n;
  }
}

export interface ApprovalHandlerOptions {
  /** Recorded as the approver in the gate. The PIN proves "someone with the PIN", not who. */
  approver?: string;
  /** Route prefix. Default `/approve`. */
  basePath?: string;
  /** Runs after a decision is stored, without delaying the response. Run `gate.execute` here. */
  onDecision?: (record: ActionRecord, decision: 'approve' | 'reject') => void | Promise<void>;
  onError?: (error: unknown) => void;
}

const SECURITY_HEADERS: Record<string, string> = {
  'Content-Type': 'text/html; charset=utf-8',
  'Cache-Control': 'no-store',
  'Referrer-Policy': 'no-referrer',
  'X-Robots-Tag': 'noindex, nofollow',
  'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};

const MAX_BODY_CHARS = 2048;

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => `&#${char.charCodeAt(0)};`);
}

const STYLE = `
:root{color-scheme:light dark;--bg:#fff;--fg:#111;--muted:#666;--line:#ddd;--ok:#0a7c3e;--no:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--muted:#999;--line:#333}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.45 system-ui,sans-serif}
main{max-width:560px;margin:0 auto;padding:16px}
h1{font-size:20px;margin:0 0 4px}
.meta{color:var(--muted);font-size:14px;margin:0 0 16px;word-break:break-all}
pre{white-space:pre-wrap;word-break:break-word;border:1px solid var(--line);border-radius:8px;padding:12px;margin:0 0 16px;font-size:14px}
label{display:block;font-size:14px;color:var(--muted);margin:0 0 4px}
#pin{width:100%;font:inherit;font-size:24px;letter-spacing:8px;text-align:center;padding:10px;border:1px solid var(--line);border-radius:10px;background:var(--bg);color:var(--fg);margin:0 0 12px}
.error{color:var(--no);font-weight:600;margin:0 0 8px}
.actions{display:flex;gap:12px}
button{flex:1;font:inherit;font-weight:600;padding:14px;border-radius:10px;border:0;color:#fff}
.approve{background:var(--ok)}.reject{background:var(--no)}
`;

function page(title: string, body: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main>${body}</main></body></html>`;
}

function message(title: string, text: string): string {
  return page(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(text)}</p>`);
}

function approvalPage(record: ActionRecord, token: string, postPath: string, error?: string): string {
  return page('Review action', `<h1>${escapeHtml(record.action)}</h1>
<p class="meta">Requested by ${escapeHtml(record.actor)}<br>Input hash ${escapeHtml(record.inputHash)}</p>
<pre>${escapeHtml(JSON.stringify(record.input, null, 2))}</pre>
<form method="post" action="${escapeHtml(postPath)}">
<input type="hidden" name="t" value="${escapeHtml(token)}">
${error ? `<p class="error" role="alert">${escapeHtml(error)}</p>` : ''}
<label for="pin">Approval PIN</label>
<input id="pin" name="pin" type="password" inputmode="numeric" pattern="[0-9]{6}" minlength="6" maxlength="6" autocomplete="off" required>
<div class="actions"><button class="reject" name="action" value="reject">Reject</button>
<button class="approve" name="action" value="approve">Approve</button></div>
</form>`);
}

const FAILURE_RESPONSE: Record<Exclude<Failure, 'not_found' | 'invalid_token'>, [number, string, string]> = {
  expired: [410, 'Link expired', 'Ask for a new approval link.'],
  pin_lockout: [403, 'Link closed', 'Too many wrong PINs. The action was rejected.'],
  locked: [429, 'Try again later', 'Approvals are paused after too many wrong PINs.'],
  unavailable: [409, 'Action unavailable', 'The action changed or is no longer pending.'],
};

/** Web-standard handler for `GET` and `POST` on `<basePath>/:id`. Works with `Bun.serve` and Hono. */
export function createApprovalHandler(
  links: ApprovalLinks,
  options: ApprovalHandlerOptions = {},
): (request: Request) => Promise<Response> {
  const basePath = options.basePath ?? '/approve';
  const approver = options.approver ?? 'approval-link';
  const onError = options.onError ?? ((error: unknown) => console.error(error));
  const respond = (status: number, html: string, extra: Record<string, string> = {}) =>
    new Response(html, { status, headers: { ...SECURITY_HEADERS, ...extra } });
  const notFound = () => respond(404, message('Not found', 'This link is not valid.'));

  return async (request) => {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(`${basePath}/`)) return notFound();
    let id: string;
    try {
      id = decodeURIComponent(url.pathname.slice(basePath.length + 1));
    } catch {
      return notFound();
    }
    if (!id || id.includes('/')) return notFound();
    const postPath = `${basePath}/${encodeURIComponent(id)}`;

    if (request.method === 'GET') {
      const token = url.searchParams.get('t') ?? '';
      const record = links.view(id, token);
      return record ? respond(200, approvalPage(record, token, postPath)) : notFound();
    }
    if (request.method !== 'POST') {
      return respond(405, message('Method not allowed', 'Use GET or POST.'), { Allow: 'GET, POST' });
    }

    const raw = await request.text();
    if (raw.length > MAX_BODY_CHARS) return respond(413, message('Request too large', 'Reload the page and try again.'));
    const form = new URLSearchParams(raw);
    const decision = form.get('action');
    if (decision !== 'approve' && decision !== 'reject') {
      return respond(400, message('Invalid action', 'Use the Approve or Reject button.'));
    }
    const token = form.get('t') ?? '';
    const result = await links[decision](id, token, form.get('pin') ?? undefined, approver);

    if (result.ok) {
      void Promise.resolve()
        .then(() => options.onDecision?.(result.record, decision))
        .catch(onError);
      return respond(200, decision === 'approve'
        ? message('Approved', 'The action will run now.')
        : message('Rejected', 'Nothing was run.'));
    }
    if (result.reason === 'not_found' || result.reason === 'invalid_token') return notFound();
    if (result.reason === 'wrong_pin') {
      const record = links.view(id, token);
      const error = `Wrong PIN. ${result.remaining} attempt${result.remaining === 1 ? '' : 's'} left.`;
      return respond(401, record ? approvalPage(record, token, postPath, error) : message('Wrong PIN', error));
    }
    const [status, title, text] = FAILURE_RESPONSE[result.reason];
    return respond(status, message(title, text));
  };
}
