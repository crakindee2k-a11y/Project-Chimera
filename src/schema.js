const { z } = require('zod');

const LANGUAGE = ['en', 'bn', 'mixed'];
const CHANNEL = ['in_app_chat', 'call_center', 'email', 'merchant_portal', 'field_agent'];
const USER_TYPE = ['customer', 'merchant', 'agent', 'unknown'];
const TRANSACTION_TYPE = ['transfer', 'payment', 'cash_in', 'cash_out', 'settlement', 'refund'];
const TRANSACTION_STATUS = ['completed', 'failed', 'pending', 'reversed'];
const EVIDENCE_VERDICT = ['consistent', 'inconsistent', 'insufficient_data'];
const CASE_TYPE = [
  'wrong_transfer',
  'payment_failed',
  'refund_request',
  'duplicate_payment',
  'merchant_settlement_delay',
  'agent_cash_in_issue',
  'phishing_or_social_engineering',
  'other'
];
const SEVERITY = ['low', 'medium', 'high', 'critical'];
const DEPARTMENT = [
  'customer_support',
  'dispute_resolution',
  'payments_ops',
  'merchant_operations',
  'agent_operations',
  'fraud_risk'
];

const LooseString = z.preprocess((value) => {
  if (value === null || value === undefined) return undefined;
  return String(value).trim();
}, z.string().min(1));

const TransactionSchema = z.object({
  transaction_id: LooseString.optional(),
  timestamp: LooseString.optional(),
  type: z.enum(TRANSACTION_TYPE).optional(),
  amount: z.preprocess((value) => {
    if (value === null || value === undefined || value === '') return undefined;
    const numberValue = Number(value);
    return Number.isFinite(numberValue) ? numberValue : value;
  }, z.number().nonnegative().optional()),
  counterparty: LooseString.optional(),
  status: z.enum(TRANSACTION_STATUS).optional()
}).passthrough();

const TicketInputSchema = z.object({
  ticket_id: LooseString,
  complaint: LooseString,
  language: z.enum(LANGUAGE).optional().default('en'),
  channel: z.enum(CHANNEL).optional(),
  user_type: z.enum(USER_TYPE).optional().default('unknown'),
  campaign_context: LooseString.optional(),
  transaction_history: z.array(TransactionSchema).optional().default([]),
  metadata: z.record(z.any()).optional().default({})
}).passthrough();

const AnalysisOutputSchema = z.object({
  ticket_id: z.string().min(1),
  relevant_transaction_id: z.string().min(1).nullable(),
  evidence_verdict: z.enum(EVIDENCE_VERDICT),
  case_type: z.enum(CASE_TYPE),
  severity: z.enum(SEVERITY),
  department: z.enum(DEPARTMENT),
  agent_summary: z.string().min(1),
  recommended_next_action: z.string().min(1),
  customer_reply: z.string().min(1),
  human_review_required: z.boolean(),
  confidence: z.number().min(0).max(1).optional(),
  reason_codes: z.array(z.string().min(1)).optional()
});

function parseTicketInput(payload) {
  return TicketInputSchema.safeParse(payload);
}

function validateAnalysisOutput(payload) {
  return AnalysisOutputSchema.safeParse(payload);
}

function fallbackOutput(ticketId = 'unknown', reason = 'invalid_request') {
  return {
    ticket_id: String(ticketId || 'unknown'),
    relevant_transaction_id: null,
    evidence_verdict: 'insufficient_data',
    case_type: 'other',
    severity: 'low',
    department: 'customer_support',
    agent_summary: 'Ticket could not be analyzed with available structured data.',
    recommended_next_action: 'Ask the customer for non-sensitive transaction details and route to customer support for manual review.',
    customer_reply: 'We could not safely verify this request yet. Please share only non-sensitive transaction details such as transaction ID, amount, and time through official support channels. Never share your PIN, OTP, password, or full card number.',
    human_review_required: true,
    confidence: 0.2,
    reason_codes: [reason]
  };
}

module.exports = {
  LANGUAGE,
  CHANNEL,
  USER_TYPE,
  TRANSACTION_TYPE,
  TRANSACTION_STATUS,
  EVIDENCE_VERDICT,
  CASE_TYPE,
  SEVERITY,
  DEPARTMENT,
  TicketInputSchema,
  AnalysisOutputSchema,
  parseTicketInput,
  validateAnalysisOutput,
  fallbackOutput
};
