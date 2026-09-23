# Agent Action Gate

A Bun/TypeScript library for agent actions that need explicit approval and at-most-once dispatch. It was generalized from approval-gated actions built for Inker's Kitsune assistant.

An agent can prepare an action and show the exact input hash. A separate approver accepts that hash. Only then can the application dispatch the action. A network error after dispatch leaves the action **uncertain**, so the agent must reconcile with the external provider instead of submitting again.

## Capabilities

- Persist proposals and audit events in SQLite.
- Deduplicate proposals by `(actor, action, idempotencyKey)`.
- Reject approval if the proposed input has changed or expired.
- Atomically claim an approved action before calling its operation.
- Record `succeeded`, `rejected`, `uncertain`, and reconciled outcomes.
- Require explicit reconciliation when an external call's result is unknown.

## Quick start

Requires Bun 1.2 or newer. From this directory:

```sh
bun test
```

```ts
import { ActionGate } from './src/index';

const gate = new ActionGate('./actions.db');
const proposal = gate.prepare({
  actor: 'marketing-agent',
  action: 'pause-campaign',
  input: { campaignId: 'example-123' },
  idempotencyKey: 'conversation-42/tool-call-1',
});

// Show proposal.input and proposal.inputHash to a human reviewer.
gate.approve(proposal.id, 'reviewer-id', proposal.inputHash);
const outcome = await gate.execute(proposal.id, async ({ campaignId }) => {
  return { providerId: await pauseCampaign(campaignId) };
});

if (outcome.status === 'uncertain') {
  // Query the provider before calling gate.reconcile(...).
}
```

`approve` is an application method, not an agent tool. Put it behind your authenticated review surface. Calling it directly from an agent would defeat the approval boundary.

## State contract

`pending → approved → executing → succeeded` is the normal path. `pending → rejected` ends a proposal. Any error thrown by the operation after dispatch moves `executing → uncertain`; an operator can then call `reconcile` with a verified outcome. Reusing a proposal or idempotency key with different input fails.

If a process crashes while an action is `executing`, inspect the provider and call `markInterruptedAsUncertain` before reconciliation. The library deliberately does not retry or infer that the external action failed.

SQLite makes the claim atomic across processes sharing the same database file. Keep the database on a local filesystem and back it up if its audit trail matters. The library does not authenticate reviewers; the embedding application must do that.

## API

See [architecture](docs/architecture.md) for data flow and failure handling. Public methods: `prepare`, `get`, `approve`, `reject`, `execute`, `history`, `markInterruptedAsUncertain`, `reconcile`, `close`.

## Verification

`bun test` uses an in-memory SQLite database and a simulated external operation. It verifies input binding, deduplication, one-time execution, and uncertain-result handling. Tests never call a paid API.

## Origin and scope

This is a standalone generalization of the approval and deduplication pattern used by Inker's assistant for board and WhatsApp actions. It contains no Inker customer data, credentials, or product-specific use cases.
