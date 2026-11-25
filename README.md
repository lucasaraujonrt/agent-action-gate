# Agent Action Gate

**Project site:** https://lucasaraujonrt.github.io/agent-action-gate/
A Bun/TypeScript library for agent actions that need explicit approval and at-most-once dispatch. It was generalized from approval-gated actions built for Inker's Kitsune assistant.

An agent can prepare an action and show the exact input hash. A separate approver accepts that hash. Only then can the application dispatch the action. A network error after dispatch leaves the action **uncertain**, so the agent must reconcile with the external provider instead of submitting again.

## Capabilities

- Persist proposals and audit events in SQLite.
- Deduplicate proposals by `(actor, action, idempotencyKey)`.
- Reject approval if the proposed input has changed or expired.
- Atomically claim an approved action before calling its operation.
- Record `succeeded`, `rejected`, `uncertain`, and reconciled outcomes.
- Require explicit reconciliation when an external call's result is unknown.
- Approve through a one-time link and a PIN, with lockouts and race safety (see [Approval links](#approval-links)).

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

## Approval links

`ApprovalLinks` is the human side of the gate. It lets a person approve or reject a pending action from a phone with a one-time link and a 6-digit PIN. It does not send the link. Delivery (chat, email, SMS) is up to you.

Threat model:

- The link is a bearer secret. A random 32-byte token is issued, and only its SHA-256 is stored. A guessed or reused token changes nothing.
- A link works once. A used, expired or locked link cannot be used again, and a new link replaces it. A link also never outlives its action: it expires at the earlier of `linkTtlMs` (72 hours by default) and the action's own `expiresAt`.
- A wrong guess costs the attacker an attempt, and the attempt is reserved before the slow PIN check runs. So 50 parallel guesses run the PIN check at most 5 times, not 50.
- 5 wrong PINs lock the action and reject it. The count belongs to the action, not to a link: `issue` refuses a locked action and keeps the count when it replaces a link. 20 wrong PINs in an hour across all links pause every approval for an hour, so collecting many links does not buy more guesses.
- The approval is bound to the input hash captured when the link was issued. If the action's input changed, the link cannot approve it.
- `GET` only reads. Every response sets `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and noindex headers, because the token is in the URL.

What it does not do:

- It does not identify who approved. The PIN proves that someone holding the link and the PIN approved, not who.
- The PIN is a second factor on top of an unguessable link, not a password. A 6-digit PIN has only a million values, so if the stored hash leaks it can be brute-forced offline in seconds. Keep the hash in a secret store, not in the repository.
- It does not stop someone who can read both your chat messages and your PIN.

```ts
import { ActionGate, ApprovalLinks, createApprovalHandler } from 'agent-action-gate';

const gate = new ActionGate('./actions.db');
const links = new ApprovalLinks({ gate, pinHash: process.env.APPROVAL_PIN_HASH!, path: './links.db' });

const proposal = gate.prepare({ actor: 'agent', action: 'send-message', input: { text: 'hi' }, idempotencyKey: 'call-1', ttlMs: 72 * 3600_000 });
const { token } = links.issue(proposal.id);
await sendToApprover(`https://approvals.example.com/approve/${proposal.id}?t=${token}`);

Bun.serve({
  fetch: createApprovalHandler(links, {
    approver: 'phone',
    onDecision: async (record, decision) => {
      if (decision === 'reject') return;
      await gate.execute(record.id, async (input) => sendMessage(input));
    },
  }),
});
```

`sendToApprover` and `sendMessage` stand for your own delivery and side-effect code. The handler uses only the web `Request` and `Response` types, so it also mounts in Hono (`app.all('/approve/*', (c) => handler(c.req.raw))`). Serve it over HTTPS. Without `path`, link state lives in memory and links die on restart.

Generate the PIN hash once and keep it in your secret store:

```sh
bun -e "import { hashPin } from './src/approval-link'; console.log(await hashPin(prompt('6-digit PIN: ')!))"
```

Run the demo with `APPROVAL_PIN_HASH='scrypt$...' bun run examples/approval-link.ts`. It prints the link and executes the action once you approve.

Decision results are `{ ok: true, record }` or `{ ok: false, reason }` with `reason` one of `not_found`, `invalid_token`, `expired`, `wrong_pin` (also carries `remaining`), `pin_lockout`, `locked` (global pause), or `unavailable` (the gate refused: not pending, expired, or input hash changed). The link and the gate use separate SQLite connections, so a crash between consuming the link and the gate update leaves the action pending with a used link. Call `issue` again to recover: it replaces a used link, but not a locked one.

If a process dies after reserving the last PIN attempt and before recording the failure, the next request finds an open link with no attempts left. It marks the link locked and rejects the action in the gate.

Options:

| Option | Where | Default | Meaning |
|---|---|---|---|
| `limits.linkTtlMs` | `ApprovalLinks` | 72 hours | Link lifetime, capped at the action's `expiresAt` |
| `limits.maxPinFailures` | `ApprovalLinks` | 5 | Wrong PINs per action before it is locked and rejected |
| `limits.globalFailuresPerHour` | `ApprovalLinks` | 20 | Wrong PINs across all links before approvals pause |
| `limits.globalLockMs` | `ApprovalLinks` | 1 hour | How long the global pause lasts |
| `approver` | handler | `approval-link` | Name recorded as the approver in the gate |
| `basePath` | handler | `/approve` | Route prefix, `<basePath>/:id?t=<token>` |
| `onDecision` | handler | none | Runs after a decision is stored, without delaying the response |
| `onError` | handler | `console.error` | Receives errors thrown by `onDecision` |

HTTP status mapping for `POST`:

| Status | Meaning |
|---|---|
| 200 | Decision stored |
| 400 | `action` is neither `approve` nor `reject` |
| 401 | Wrong PIN, with the attempts left |
| 403 | Too many wrong PINs, link closed and action rejected |
| 404 | Unknown action, wrong token or used link. All look the same |
| 405 | Method other than `GET` or `POST` |
| 409 | The action changed or is no longer pending |
| 410 | Link expired |
| 413 | Body over 2048 bytes, refused before it is fully read |
| 429 | Global pause after too many wrong PINs |

## API

See [architecture](docs/architecture.md) for data flow and failure handling. Public methods: `prepare`, `get`, `approve`, `reject`, `execute`, `history`, `markInterruptedAsUncertain`, `reconcile`, `close`.

Approval links add `ApprovalLinks` with `issue`, `view`, `approve`, `reject` and `close`, plus `createApprovalHandler`, `hashPin`, `parsePinHash` and `verifyPin`.

## Verification

`bun test` uses an in-memory SQLite database and a simulated external operation. It verifies input binding, deduplication, one-time execution, and uncertain-result handling. Tests never call a paid API.

## Origin and scope

This is a standalone generalization of the approval and deduplication pattern used by Inker's assistant for board and WhatsApp actions. It contains no Inker customer data, credentials, or product-specific use cases.
