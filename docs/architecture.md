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

## Approval links

`ApprovalLinks` sits in front of `approve` and `reject`. It keeps its own SQLite tables: one row per action (token hash, input hash, expiry, wrong-PIN count, status), a short log of recent wrong PINs, and a global lock. The token is stored as a hash and cleared when the link is used.

A decision runs in three steps. First one transaction checks the token and expiry and reserves a PIN attempt, so parallel guesses cannot all reach the slow PIN check. Then the PIN is checked. Then a second transaction consumes the link before the gate is called, so two requests with a correct PIN cannot both decide.

| Failure | Result |
|---|---|
| Wrong or reused token | Nothing changes, the response looks like an unknown link |
| Wrong PIN limit reached | Link locked and action rejected, `issue` refuses it from then on |
| Process dies after reserving the last attempt | Next request locks the link and rejects the action |
| Process dies after consuming the link, before the gate call | Action stays pending, `issue` replaces the used link |
| Link older than the action | Cannot exist: expiry is capped at the action's own |
