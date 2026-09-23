# Architecture

`ActionGate` stores a proposal and its canonical JSON input hash in SQLite. The caller must provide a stable idempotency key for each intended side effect. A review surface reads the proposal, displays its input, and submits the hash the reviewer accepted.

`execute` performs a conditional SQLite update from `approved` to `executing`. Only the process that changes that row calls the operation. Its return value is persisted as `succeeded`. An exception becomes `uncertain`, because the external provider may have committed the operation before the error reached this process.

The database contains an append-only `action_events` table for the local audit view. The current adapter is Bun SQLite; there is no remote database adapter in this release. The operation callback owns authentication, authorization, provider rate limits, and verification of the external result.

## Failure handling

| Failure | Result |
|---|---|
| Same key and same input | Existing proposal returned |
| Same key and changed input | Rejected |
| Expired or changed proposal | Approval rejected |
| Duplicate execute | Rejected before callback |
| Callback throws or times out | `uncertain`, no automatic retry |
| Process dies while executing | Operator checks provider, then marks uncertain and reconciles |

Each SQLite state transition and corresponding audit event is committed in one transaction. Do not use this package as a distributed workflow engine or as the sole source of truth for an external provider's state.
