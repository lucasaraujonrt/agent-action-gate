import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { Database } from 'bun:sqlite';

export type ActionStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'executing'
  | 'succeeded'
  | 'uncertain'
  | 'failed';

export interface ActionRecord<T = unknown> {
  id: string;
  actor: string;
  action: string;
  input: T;
  inputHash: string;
  idempotencyKey: string;
  status: ActionStatus;
  createdAt: number;
  expiresAt: number;
  approvedBy: string | null;
  result: unknown | null;
  error: string | null;
}

export interface PrepareAction<T> {
  actor: string;
  action: string;
  input: T;
  idempotencyKey: string;
  ttlMs?: number;
}

function canonical(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonical(object[key])}`).join(',')}}`;
}

function hashInput(input: unknown): string {
  const serialized = canonical(input);
  if (!serialized) throw new Error('input must be JSON serializable');
  return createHash('sha256').update(serialized).digest('hex');
}

function required(value: string, label: string): string {
  const trimmed = value.trim();
  if (!trimmed) throw new Error(`${label} is required`);
  return trimmed;
}

export class ActionGate {
  private readonly db: Database;

  constructor(path = ':memory:') {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new Database(path, { create: true });
    this.db.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS actions (
        id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        input_json TEXT NOT NULL,
        input_hash TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        approved_by TEXT,
        result_json TEXT,
        error TEXT,
        UNIQUE(actor, action, idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS action_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action_id TEXT NOT NULL REFERENCES actions(id),
        at INTEGER NOT NULL,
        kind TEXT NOT NULL,
        details_json TEXT NOT NULL
      );
    `);
  }

  private event(id: string, kind: string, details: unknown = {}): void {
    this.db.prepare('INSERT INTO action_events (action_id,at,kind,details_json) VALUES (?,?,?,?)')
      .run(id, Date.now(), kind, JSON.stringify(details));
  }

  private recorded<T>(change: () => T, id: string, kind: string, details: unknown = {}): T {
    return this.db.transaction(() => {
      const value = change();
      this.event(id, kind, details);
      return value;
    })();
  }

  prepare<T>(request: PrepareAction<T>): ActionRecord<T> {
    const actor = required(request.actor, 'actor');
    const action = required(request.action, 'action');
    const idempotencyKey = required(request.idempotencyKey, 'idempotencyKey');
    const ttlMs = request.ttlMs ?? 15 * 60_000;
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('ttlMs must be a positive integer');
    const serialized = JSON.stringify(request.input);
    if (serialized === undefined) throw new Error('input must be JSON serializable');
    const normalizedInput = JSON.parse(serialized) as T;
    const inputHash = hashInput(normalizedInput);
    const now = Date.now();
    const id = randomUUID();
    this.db.transaction(() => {
      const inserted = this.db.prepare(`
        INSERT OR IGNORE INTO actions
        (id, actor, action, input_json, input_hash, idempotency_key, status, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
      `).run(id, actor, action, serialized, inputHash, idempotencyKey, now, now + ttlMs);
      if (inserted.changes === 1) this.event(id, 'prepared', { actor, action, inputHash });
    })();
    const record = this.db.prepare('SELECT id FROM actions WHERE actor=? AND action=? AND idempotency_key=?')
      .get(actor, action, idempotencyKey) as { id: string };
    const existing = this.get<T>(record.id);
    if (existing.inputHash !== inputHash) throw new Error('idempotency key already used with different input');
    return existing;
  }

  get<T = unknown>(id: string): ActionRecord<T> {
    const row = this.db.prepare('SELECT * FROM actions WHERE id=?').get(id) as Record<string, unknown> | null;
    if (!row) throw new Error('action not found');
    return {
      id: row.id as string,
      actor: row.actor as string,
      action: row.action as string,
      input: JSON.parse(row.input_json as string) as T,
      inputHash: row.input_hash as string,
      idempotencyKey: row.idempotency_key as string,
      status: row.status as ActionStatus,
      createdAt: row.created_at as number,
      expiresAt: row.expires_at as number,
      approvedBy: row.approved_by as string | null,
      result: row.result_json ? JSON.parse(row.result_json as string) : null,
      error: row.error as string | null,
    };
  }

  approve(id: string, approver: string, inputHash: string): ActionRecord {
    required(approver, 'approver');
    this.recorded(() => {
      const changed = this.db.prepare(`
        UPDATE actions SET status='approved', approved_by=?
        WHERE id=? AND input_hash=? AND status='pending' AND expires_at>?
      `).run(approver, id, inputHash, Date.now()).changes;
      if (changed !== 1) throw new Error('action unavailable, expired, or input hash mismatch');
    }, id, 'approved', { approver });
    return this.get(id);
  }

  reject(id: string, approver: string): ActionRecord {
    required(approver, 'approver');
    this.recorded(() => {
      const changed = this.db.prepare(`
        UPDATE actions SET status='rejected', approved_by=? WHERE id=? AND status='pending'
      `).run(approver, id).changes;
      if (changed !== 1) throw new Error('action is not pending');
    }, id, 'rejected', { approver });
    return this.get(id);
  }

  async execute<TInput, TResult>(
    id: string,
    operation: (input: TInput) => Promise<TResult>,
  ): Promise<ActionRecord<TInput>> {
    this.recorded(() => {
      const changed = this.db.prepare(`
        UPDATE actions SET status='executing'
        WHERE id=? AND status='approved' AND expires_at>?
      `).run(id, Date.now()).changes;
      if (changed !== 1) throw new Error('action is not approved, is expired, or was already executed');
    }, id, 'executing');
    const record = this.get<TInput>(id);
    try {
      const result = await operation(record.input);
      this.recorded(() => {
        this.db.prepare(`UPDATE actions SET status='succeeded', result_json=? WHERE id=? AND status='executing'`)
          .run(JSON.stringify(result ?? null), id);
      }, id, 'succeeded');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.recorded(() => {
        this.db.prepare(`UPDATE actions SET status='uncertain', error=? WHERE id=? AND status='executing'`)
          .run(message, id);
      }, id, 'uncertain', { error: message });
    }
    return this.get<TInput>(id);
  }

  reconcile(id: string, outcome: { status: 'succeeded'; result: unknown } | { status: 'failed'; error: string }): ActionRecord {
    this.recorded(() => {
      const changed = this.db.prepare(`
        UPDATE actions SET status=?, result_json=?, error=? WHERE id=? AND status='uncertain'
      `).run(outcome.status, outcome.status === 'succeeded' ? JSON.stringify(outcome.result) : null,
        outcome.status === 'failed' ? outcome.error : null, id).changes;
      if (changed !== 1) throw new Error('action is not uncertain');
    }, id, 'reconciled', { status: outcome.status });
    return this.get(id);
  }

  history(id: string): Array<{ at: number; kind: string; details: unknown }> {
    this.get(id);
    const events = this.db.prepare('SELECT at,kind,details_json FROM action_events WHERE action_id=? ORDER BY id')
      .all(id) as Array<{ at: number; kind: string; details_json: string }>;
    return events.map((event) => ({ at: event.at, kind: event.kind, details: JSON.parse(event.details_json) }));
  }

  markInterruptedAsUncertain(id: string): ActionRecord {
    this.recorded(() => {
      const changed = this.db.prepare("UPDATE actions SET status='uncertain', error='execution interrupted' WHERE id=? AND status='executing'")
        .run(id).changes;
      if (changed !== 1) throw new Error('action is not executing');
    }, id, 'uncertain', { error: 'execution interrupted' });
    return this.get(id);
  }

  close(): void {
    this.db.close();
  }
}
