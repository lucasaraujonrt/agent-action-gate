import { ActionGate, ApprovalLinks, createApprovalHandler } from '../src/index';

const pinHash = process.env.APPROVAL_PIN_HASH;
if (!pinHash) {
  console.error('APPROVAL_PIN_HASH is not set. Generate one with the command in the README ("Approval links").');
  process.exit(1);
}

const port = Number(process.env.PORT ?? 3000);
const baseUrl = process.env.BASE_URL ?? `http://localhost:${port}`;

const gate = new ActionGate('./demo-actions.db');
const links = new ApprovalLinks({ gate, pinHash, path: './demo-links.db' });

const action = gate.prepare({
  actor: 'demo-agent',
  action: 'send-message',
  input: { to: 'team-channel', text: 'Deploy finished' },
  idempotencyKey: `demo-${Date.now()}`,
  ttlMs: 24 * 60 * 60_000,
});
// The link expires at the earlier of its own ttl (72 hours) and the action's expiry (24 hours here).
const { token, expiresAt } = links.issue(action.id);

const handler = createApprovalHandler(links, {
  approver: 'demo-approver',
  onDecision: async (record, decision) => {
    if (decision === 'reject') return console.log(`rejected ${record.id}`);
    const done = await gate.execute<{ to: string; text: string }, string>(record.id, async (input) => {
      console.log(`sending "${input.text}" to ${input.to}`);
      return 'sent';
    });
    console.log(`executed ${done.id}: ${done.status}`);
  },
});

Bun.serve({ port, fetch: handler });

// Delivery is the caller's job. Print the link where a real app would send a message or email.
console.log(`Approval link (expires ${new Date(expiresAt).toISOString()}):`);
console.log(`${baseUrl}/approve/${action.id}?t=${token}`);
