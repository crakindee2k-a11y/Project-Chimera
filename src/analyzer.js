const { applySafety, hasFraudRisk, hasPromptInjection, resolveLanguage } = require('./safety');
const { validateAnalysisOutput, fallbackOutput } = require('./schema');

const CASE_RULES = [
  {
    caseType: 'duplicate_payment',
    patterns: [/duplicate/i, /charged\s+twice/i, /deduct(?:ed)?\s+twice/i, /both\s+were\s+deducted/i, /paid.*deduct(?:ed)?\s+twice/i, /paid.*twice/i, /two\s+times/i, /double\s+(?:charge|payment|deduct)/i, /দুইবার|ডাবল/i]
  },
  {
    caseType: 'agent_cash_in_issue',
    patterns: [/cash[-\s]?in/i, /cash\s+in/i, /agent/i, /deposited/i, /জমা|ক্যাশ\s*ইন/i]
  },
  {
    caseType: 'payment_failed',
    patterns: [/payment\s+failed/i, /failed.*(?:deducted|debit|charged|refund)/i, /(?:deducted|debit|charged).*failed/i, /recharge.*failed/i, /app\s+showed\s+failed/i, /merchant\s+did(?:\s+not|n't)\s+receive/i, /ব্যর্থ|ফেইল|কেটে/i]
  },
  {
    caseType: 'refund_request',
    patterns: [/refund/i, /return\s+(?:my\s+)?money/i, /changed\s+my\s+mind/i, /cancel(?:led)?\s+order/i, /not\s+delivered/i, /reversal/i, /রিফান্ড|ফেরত/i]
  },
  {
    caseType: 'merchant_settlement_delay',
    patterns: [/settlement/i, /settled/i, /payout/i, /merchant\s+portal/i, /merchant.*(?:settlement|payout|not\s+settled)/i, /সেটেলমেন্ট|মার্চেন্ট/i]
  },
  {
    caseType: 'wrong_transfer',
    patterns: [/wrong\s+(?:number|person|recipient|account)/i, /sent\s+to\s+(?:the\s+)?wrong/i, /typed\s+it\s+wrong/i, /by\s+mistake/i, /reverse\s+it/i, /sent\s+\d+.*(?:did(?:\s+not|n't)\s+get|has(?:\s+not|n't)\s+received)/i, /sent.*(?:brother|friend|sister|mother|father).*(?:did(?:\s+not|n't)\s+get|has(?:\s+not|n't)\s+received)/i, /ভুল\s+(?:নাম্বার|নম্বরে|ব্যক্তি)/i]
  }
];

const TYPE_BY_CASE = {
  wrong_transfer: ['transfer'],
  payment_failed: ['payment'],
  refund_request: ['refund', 'payment'],
  duplicate_payment: ['payment', 'transfer'],
  merchant_settlement_delay: ['settlement'],
  agent_cash_in_issue: ['cash_in']
};

function analyzeTicket(input) {
  try {
    const context = buildContext(input);
    const caseType = classifyCase(context);
    const relevant = selectRelevantTransaction(context, caseType);
    const evidence = determineEvidence(context, caseType, relevant);
    const output = buildOutput(context, caseType, relevant, evidence);
    const safe = applySafety(output, input);
    const validation = validateAnalysisOutput(safe);
    if (!validation.success) {
      return fallbackOutput(input.ticket_id, 'output_validation_failed');
    }
    return validation.data;
  } catch (error) {
    return fallbackOutput(input?.ticket_id, 'analysis_error');
  }
}

function buildContext(input) {
  const complaint = String(input.complaint || '');
  const normalized = complaint.toLowerCase();
  const amounts = extractAmounts(complaint);
  const transactionIds = extractTransactionIds(complaint);
  const phoneHints = extractPhoneHints(complaint);
  const transactions = (input.transaction_history || []).map((tx, index) => normalizeTransaction(tx, index));
  return {
    input,
    complaint,
    normalized,
    amounts,
    transactionIds,
    phoneHints,
    transactions,
    hasPromptInjection: hasPromptInjection(complaint),
    hasFraudRisk: hasFraudRisk(complaint)
  };
}

function classifyCase(context) {
  if (context.hasFraudRisk) return 'phishing_or_social_engineering';
  for (const rule of CASE_RULES) {
    if (rule.patterns.some((pattern) => pattern.test(context.complaint))) {
      return rule.caseType;
    }
  }
  return 'other';
}

function selectRelevantTransaction(context, caseType) {
  if (!context.transactions.length || caseType === 'phishing_or_social_engineering' || caseType === 'other') {
    return null;
  }

  if (isAmbiguousWrongTransfer(context, caseType)) {
    context.ambiguousMatch = true;
    return null;
  }

  if (caseType === 'duplicate_payment') {
    const duplicate = findDuplicateTransaction(context.transactions, context.amounts);
    if (duplicate) return duplicate;
  }

  const candidates = context.transactions.map((tx) => ({
    tx,
    score: scoreTransaction(context, caseType, tx)
  })).filter((entry) => entry.score > 0);

  if (!candidates.length) return null;
  candidates.sort((a, b) => b.score - a.score || compareTimestampDesc(a.tx, b.tx) || b.tx.index - a.tx.index);
  return candidates[0].tx;
}

function scoreTransaction(context, caseType, tx) {
  let score = 0;
  if (tx.transaction_id && context.transactionIds.includes(tx.transaction_id.toUpperCase())) score += 100;
  if (context.amounts.some((amount) => amountsClose(amount, tx.amount))) score += 35;
  if ((TYPE_BY_CASE[caseType] || []).includes(tx.type)) score += 25;
  if (context.phoneHints.some((hint) => comparableCounterparty(tx.counterparty).includes(hint))) score += 20;

  if (caseType === 'payment_failed' && ['failed', 'pending'].includes(tx.status)) score += 20;
  if (caseType === 'wrong_transfer' && tx.status === 'completed') score += 15;
  if (caseType === 'refund_request' && ['reversed', 'completed'].includes(tx.status)) score += 15;
  if (caseType === 'merchant_settlement_delay' && ['pending', 'completed'].includes(tx.status)) score += 15;
  if (caseType === 'agent_cash_in_issue' && ['completed', 'pending'].includes(tx.status)) score += 15;
  if (caseType === 'duplicate_payment' && ['completed', 'pending'].includes(tx.status)) score += 15;

  if (!context.amounts.length && (TYPE_BY_CASE[caseType] || []).includes(tx.type)) score += 10;
  return score;
}

function determineEvidence(context, caseType, relevant) {
  const reasonCodes = [];
  let evidenceVerdict = 'insufficient_data';
  let confidence = 0.45;

  if (caseType === 'phishing_or_social_engineering') {
    return { evidenceVerdict, confidence: 0.85, reasonCodes: ['fraud_risk'] };
  }

  if (context.hasPromptInjection) reasonCodes.push('prompt_injection_ignored');

  if (!relevant) {
    if (context.ambiguousMatch) {
      reasonCodes.push('ambiguous_match', 'needs_clarification');
      return { evidenceVerdict, confidence: 0.65, reasonCodes };
    }
    reasonCodes.push('no_matching_transaction');
    return { evidenceVerdict, confidence, reasonCodes };
  }

  reasonCodes.push('transaction_match');

  if (caseType === 'wrong_transfer') {
    reasonCodes.push('wrong_transfer_claim');
    const repeatCount = countComparableCounterpartyTransfers(context.transactions, relevant);
    if (repeatCount >= 2) {
      evidenceVerdict = 'inconsistent';
      confidence = 0.75;
      reasonCodes.push('established_recipient_pattern', 'evidence_inconsistent');
    } else if (relevant.type === 'transfer' && relevant.status === 'completed') {
      evidenceVerdict = 'consistent';
      confidence = 0.9;
      reasonCodes.push('wrong_transfer');
    } else {
      evidenceVerdict = 'inconsistent';
      confidence = 0.65;
      reasonCodes.push('transaction_status_or_type_mismatch');
    }
  } else if (caseType === 'payment_failed') {
    reasonCodes.push('payment_failed');
    if (relevant.type === 'payment' && ['failed', 'pending'].includes(relevant.status)) {
      evidenceVerdict = 'consistent';
      confidence = 0.9;
      reasonCodes.push('potential_balance_deduction');
    } else if (relevant.type === 'payment' && relevant.status === 'completed' && /failed/i.test(context.complaint)) {
      evidenceVerdict = 'inconsistent';
      confidence = 0.7;
      reasonCodes.push('status_contradicts_failed_claim');
    } else {
      evidenceVerdict = 'insufficient_data';
      confidence = 0.55;
    }
  } else if (caseType === 'refund_request') {
    reasonCodes.push('refund_request');
    if (['payment', 'refund'].includes(relevant.type) && ['completed', 'reversed', 'pending'].includes(relevant.status)) {
      evidenceVerdict = 'consistent';
      confidence = relevant.status === 'reversed' ? 0.9 : 0.75;
    } else {
      evidenceVerdict = 'insufficient_data';
      confidence = 0.55;
    }
  } else if (caseType === 'duplicate_payment') {
    reasonCodes.push('duplicate_payment');
    if (hasDuplicatePair(context.transactions, relevant)) {
      evidenceVerdict = 'consistent';
      confidence = 0.9;
      reasonCodes.push('duplicate_transaction_pattern');
    } else {
      evidenceVerdict = 'insufficient_data';
      confidence = 0.55;
    }
  } else if (caseType === 'merchant_settlement_delay') {
    reasonCodes.push('merchant_settlement_delay');
    if (relevant.type === 'settlement' && ['pending', 'completed'].includes(relevant.status)) {
      evidenceVerdict = 'consistent';
      confidence = 0.85;
    } else {
      evidenceVerdict = 'insufficient_data';
      confidence = 0.55;
    }
  } else if (caseType === 'agent_cash_in_issue') {
    reasonCodes.push('agent_cash_in_issue');
    if (relevant.type === 'cash_in' && ['completed', 'pending'].includes(relevant.status)) {
      evidenceVerdict = 'consistent';
      confidence = 0.88;
    } else {
      evidenceVerdict = 'inconsistent';
      confidence = 0.65;
      reasonCodes.push('cash_in_status_or_type_mismatch');
    }
  }

  if (context.hasPromptInjection) reasonCodes.push('prompt_injection_ignored');
  return { evidenceVerdict, confidence, reasonCodes: unique(reasonCodes) };
}

function buildOutput(context, caseType, relevant, evidence) {
  const input = context.input;
  const amount = relevant?.amount ?? context.amounts[0];
  const amountText = formatAmount(amount);
  const txId = relevant?.transaction_id || null;
  const counterparty = relevant?.counterparty;
  const reasonCodes = new Set(evidence.reasonCodes || []);
  let severity = determineSeverity(context, caseType, relevant, evidence.evidenceVerdict);
  let department = determineDepartment(caseType);
  // A contested refund (disputed charge, non-delivery, unauthorized, or evidence that
  // contradicts the claim) is a dispute, not a routine support request. Plain change-of-mind
  // refunds stay with customer_support.
  if (caseType === 'refund_request' && isContestedRefund(context, evidence.evidenceVerdict)) {
    department = 'dispute_resolution';
    reasonCodes.add('refund_contested');
  }
  let humanReview = shouldRequireHumanReview(context, caseType, relevant, evidence.evidenceVerdict, severity);
  let summary = '';
  let action = '';
  let reply = '';

  switch (caseType) {
    case 'wrong_transfer':
      summary = txId
        ? `Customer claims ${txId}${amountText ? ` (${amountText})` : ''}${counterparty ? ` to ${counterparty}` : ''} was sent to the wrong recipient${evidence.evidenceVerdict === 'inconsistent' ? ', but transaction history suggests an established recipient pattern' : ''}.`
        : 'Customer reports a wrong transfer, but no matching transaction was found.';
      action = evidence.evidenceVerdict === 'inconsistent'
        ? 'Flag for human review. Verify whether the recipient was genuinely unintended given the prior transaction pattern.'
        : `Verify ${txId || 'the transfer'} details with the customer and initiate the wrong-transfer dispute workflow per policy.`;
      reply = `We have received your request${txId ? ` regarding transaction ${txId}` : ''}. Please do not share your PIN or OTP with anyone. Our dispute team will review the case carefully and contact you through official support channels.`;
      reasonCodes.add(evidence.evidenceVerdict === 'inconsistent' ? 'evidence_inconsistent' : 'dispute_initiated');
      break;

    case 'payment_failed':
      summary = txId
        ? `Customer reports a failed payment${amountText ? ` of ${amountText}` : ''}${txId ? ` (${txId})` : ''} with a possible balance deduction.`
        : 'Customer reports a failed payment with possible balance deduction, but no matching transaction was found.';
      action = `Investigate ${txId || 'the payment'} ledger status. If balance was deducted on a failed payment, initiate the automatic reversal flow within standard SLA.`;
      reply = `We have noted that ${txId ? `transaction ${txId}` : 'this payment'} may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone.`;
      break;

    case 'refund_request':
      summary = txId
        ? `Customer requests refund review for ${txId}${amountText ? ` (${amountText})` : ''}.`
        : 'Customer requests a refund, but no matching transaction was found.';
      action = `Check refund eligibility for ${txId || 'the transaction'}. For completed merchant payments, eligibility depends on the merchant's own policy. Update the customer through official support channels.`;
      reply = `We have received your refund request${txId ? ` for transaction ${txId}` : ''}. Refunds for completed merchant payments depend on the merchant's own policy, and any eligible amount will be returned through official channels. Please do not share your PIN or OTP with anyone.`;
      break;

    case 'duplicate_payment':
      summary = txId
        ? `Customer reports a possible duplicate payment. ${txId}${amountText ? ` (${amountText})` : ''} appears related to another similar transaction.`
        : 'Customer reports a possible duplicate payment, but matching duplicate evidence was not found.';
      action = `Compare ${txId || 'the reported transaction'} with nearby same-amount payments and initiate duplicate-payment review if confirmed.`;
      reply = `We have noted your duplicate-payment concern${txId ? ` regarding transaction ${txId}` : ''}. Our payments team will review the transaction records and any eligible duplicate amount will be returned through official channels. Please do not share your PIN or OTP with anyone.`;
      break;

    case 'merchant_settlement_delay':
      summary = txId
        ? `Merchant reports settlement delay for ${txId}${amountText ? ` (${amountText})` : ''}.`
        : 'Merchant reports a settlement delay, but no settlement transaction was found.';
      action = `Route ${txId || 'the settlement issue'} to merchant operations to verify settlement status and SLA.`;
      reply = `We have received your settlement concern${txId ? ` for transaction ${txId}` : ''}. Our merchant operations team will review the status and update you through official channels.`;
      break;

    case 'agent_cash_in_issue':
      summary = txId
        ? `Customer reports a cash-in issue for ${txId}${amountText ? ` (${amountText})` : ''}${counterparty ? ` from ${counterparty}` : ''}.`
        : 'Customer reports a cash-in issue, but no matching cash-in transaction was found.';
      action = `Verify ${txId || 'the cash-in'} with agent records and route to agent operations for reconciliation.`;
      reply = `We have noted your cash-in concern${txId ? ` regarding transaction ${txId}` : ''}. Our agent operations team will review the records and contact you through official support channels. Please do not share your PIN or OTP with anyone.`;
      break;

    case 'phishing_or_social_engineering':
      summary = 'Complaint indicates possible fraud, phishing, or social-engineering risk.';
      action = 'Escalate immediately to fraud risk. Preserve complaint details, review account activity, and contact the customer only through official channels.';
      reply = 'We have flagged this as a possible fraud or social-engineering concern. Do not share your PIN, OTP, password, or full card number with anyone, do not click unknown links, and use only official support channels. Our fraud risk team will review the case.';
      break;

    default:
      summary = 'Complaint does not contain enough evidence to classify into a specific transaction case.';
      action = 'Ask for non-sensitive details such as transaction ID, amount, date, and channel, then route to customer support for manual triage.';
      reply = 'We need more non-sensitive details to review this request, such as transaction ID, amount, date, and channel. Please share details only through official support channels and never share your PIN, OTP, password, or full card number.';
      break;
  }

  // Localize customer_reply to Bangla when the complaint is Bangla. Phishing replies are
  // localized later in applySafety (fraud path overrides the reply entirely).
  if (resolveLanguage(input) === 'bn' && caseType !== 'phishing_or_social_engineering') {
    reply = banglaReply(caseType, txId);
  }

  if (context.ambiguousMatch && caseType === 'wrong_transfer') humanReview = false;
  else if (evidence.evidenceVerdict === 'insufficient_data') humanReview = true;

  return {
    ticket_id: input.ticket_id,
    relevant_transaction_id: txId,
    evidence_verdict: evidence.evidenceVerdict,
    case_type: caseType,
    severity,
    department,
    agent_summary: summary,
    recommended_next_action: action,
    customer_reply: reply,
    human_review_required: humanReview,
    confidence: Number(evidence.confidence.toFixed(2)),
    reason_codes: unique(Array.from(reasonCodes))
  };
}

function determineSeverity(context, caseType, relevant, evidenceVerdict) {
  const amount = relevant?.amount ?? context.amounts[0] ?? 0;
  if (caseType === 'phishing_or_social_engineering') return 'critical';
  if (caseType === 'other') return 'low';
  if (evidenceVerdict === 'inconsistent') return amount >= 5000 ? 'high' : 'medium';
  if (['duplicate_payment', 'agent_cash_in_issue'].includes(caseType)) return 'high';
  if (caseType === 'wrong_transfer') return amount >= 5000 ? 'high' : 'medium';
  if (caseType === 'payment_failed') return amount >= 1000 || /deduct/i.test(context.complaint) ? 'high' : 'medium';
  if (caseType === 'merchant_settlement_delay') return amount >= 10000 || context.input.user_type === 'merchant' ? 'high' : 'medium';
  if (caseType === 'refund_request') return amount >= 3000 ? 'medium' : 'low';
  return 'medium';
}

function determineDepartment(caseType) {
  return {
    wrong_transfer: 'dispute_resolution',
    payment_failed: 'payments_ops',
    refund_request: 'customer_support',
    duplicate_payment: 'payments_ops',
    merchant_settlement_delay: 'merchant_operations',
    agent_cash_in_issue: 'agent_operations',
    phishing_or_social_engineering: 'fraud_risk',
    other: 'customer_support'
  }[caseType] || 'customer_support';
}

const REFUND_CONTEST_PATTERN = /\b(not\s+delivered|did(?:\s+not|n't)\s+(?:deliver|arrive|receive|get)|never\s+(?:received|arrived|delivered)|dispute[d]?|unauthori[sz]ed|did(?:\s+not|n't)\s+authori[sz]e|defective|damaged|wrong\s+item|fake\s+product|scam|fraudulent)\b/i;
const REFUND_CONTEST_PATTERN_BN = /(ডেলিভারি|পণ্য|প্রোডাক্ট).{0,20}(পাইনি|আসেনি|পাইনাই)|নষ্ট|ভুল\s*পণ্য|ভাঙ্গা|নকল/;

function isContestedRefund(context, evidenceVerdict) {
  if (evidenceVerdict === 'inconsistent') return true;
  return REFUND_CONTEST_PATTERN.test(context.complaint) || REFUND_CONTEST_PATTERN_BN.test(context.complaint);
}

function shouldRequireHumanReview(context, caseType, relevant, evidenceVerdict, severity) {
  if (['critical', 'high'].includes(severity)) return true;
  if (['wrong_transfer', 'agent_cash_in_issue', 'merchant_settlement_delay', 'phishing_or_social_engineering'].includes(caseType)) return true;
  if (['inconsistent', 'insufficient_data'].includes(evidenceVerdict)) return true;
  if (context.hasPromptInjection || context.hasFraudRisk) return true;
  if ((relevant?.amount || 0) >= 5000) return true;
  return false;
}

function normalizeTransaction(tx, index) {
  return {
    ...tx,
    index,
    transaction_id: tx.transaction_id ? String(tx.transaction_id).trim() : null,
    timestamp: tx.timestamp ? String(tx.timestamp).trim() : null,
    type: tx.type || null,
    amount: Number.isFinite(Number(tx.amount)) ? Number(tx.amount) : null,
    counterparty: tx.counterparty ? String(tx.counterparty).trim() : null,
    status: tx.status || null
  };
}

function extractAmounts(text) {
  // Strip tokens whose digits would otherwise be misread as monetary amounts:
  // transaction/reference IDs, phone numbers, ISO dates/timestamps, and clock times.
  const cleaned = String(text || '')
    .replace(/\b[A-Za-z]{2,}-?\d{3,}\b/g, ' ')
    .replace(/(?:\+?88)?01[0-9\s-]{8,13}/g, ' ')
    .replace(/\d{4}-\d{2}-\d{2}(?:[t\s]\d{2}:\d{2}(?::\d{2})?z?)?/gi, ' ')
    .replace(/\b\d{1,2}:\d{2}(?::\d{2})?\b/g, ' ')
    .replace(/\b\d{1,2}\s*(?:am|pm)\b/gi, ' ');

  // Prefer currency-anchored amounts (৳, BDT, Tk, Taka, টাকা). Fall back to bare numbers
  // only when no currency-anchored amount is present.
  const anchored = [];
  const anchoredRe = /(?:৳|bdt|tk|taka|টাকা)\s*([0-9][0-9,]*(?:\.\d+)?)|([0-9][0-9,]*(?:\.\d+)?)\s*(?:৳|bdt|tk|taka|টাকা)/gi;
  let match;
  while ((match = anchoredRe.exec(cleaned)) !== null) {
    anchored.push(Number(String(match[1] || match[2]).replace(/,/g, '')));
  }
  const pool = anchored.length
    ? anchored
    : (cleaned.match(/\b[0-9][0-9,]*(?:\.\d+)?\b/g) || []).map((value) => Number(value.replace(/,/g, '')));

  return unique(pool.filter((n) => Number.isFinite(n) && n > 0 && n < 100000000));
}

function extractTransactionIds(text) {
  return unique((String(text || '').match(/\b[A-Z]{2,}-?\d{3,}\b/gi) || []).map((id) => id.toUpperCase()));
}

function extractPhoneHints(text) {
  const raw = String(text || '').match(/(?:\+?88)?01[0-9\s-]{8,13}/g) || [];
  return unique(raw.map((value) => value.replace(/\D/g, '').slice(-8)).filter(Boolean));
}

function comparableCounterparty(value) {
  return String(value || '').replace(/\D/g, '').slice(-12);
}

function amountsClose(left, right) {
  if (!Number.isFinite(left) || !Number.isFinite(right)) return false;
  return Math.abs(Number(left) - Number(right)) < 0.01;
}

function compareTimestampDesc(a, b) {
  const at = Date.parse(a.timestamp || '');
  const bt = Date.parse(b.timestamp || '');
  if (!Number.isFinite(at) && !Number.isFinite(bt)) return 0;
  if (!Number.isFinite(at)) return 1;
  if (!Number.isFinite(bt)) return -1;
  return bt - at;
}

function isAmbiguousWrongTransfer(context, caseType) {
  if (caseType !== 'wrong_transfer' || context.transactionIds.length || context.phoneHints.length) return false;
  const matching = context.transactions.filter((tx) => tx.type === 'transfer'
    && (!context.amounts.length || context.amounts.some((amount) => amountsClose(amount, tx.amount))));
  const completed = matching.filter((tx) => tx.status === 'completed');
  const counterparties = new Set(completed.map((tx) => comparableCounterparty(tx.counterparty)).filter(Boolean));
  return completed.length >= 2 && counterparties.size >= 2;
}

function findDuplicateTransaction(transactions, amounts) {
  const groups = new Map();
  for (const tx of transactions) {
    const key = [tx.type || 'unknown', tx.amount ?? 'unknown', comparableCounterparty(tx.counterparty)].join('|');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(tx);
  }
  const duplicates = Array.from(groups.values())
    .filter((group) => group.length >= 2)
    .flatMap((group) => group)
    .filter((tx) => !amounts.length || amounts.some((amount) => amountsClose(amount, tx.amount)));
  duplicates.sort((a, b) => compareTimestampDesc(a, b) || b.index - a.index);
  return duplicates[0] || null;
}

function hasDuplicatePair(transactions, relevant) {
  if (!relevant) return false;
  return transactions.some((tx) => tx !== relevant
    && tx.type === relevant.type
    && amountsClose(tx.amount, relevant.amount)
    && comparableCounterparty(tx.counterparty) === comparableCounterparty(relevant.counterparty));
}

function countComparableCounterpartyTransfers(transactions, relevant) {
  const counterparty = comparableCounterparty(relevant.counterparty);
  if (!counterparty) return 0;
  return transactions.filter((tx) => tx.type === 'transfer'
    && comparableCounterparty(tx.counterparty) === counterparty
    && tx.transaction_id !== relevant.transaction_id).length;
}

function formatAmount(amount) {
  return Number.isFinite(Number(amount)) ? `${Number(amount)} BDT` : '';
}

const BN_REPLIES = {
  wrong_transfer: (t) => `আপনার অনুরোধ${t ? ` (লেনদেন ${t})` : ''} আমরা গ্রহণ করেছি। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না। আমাদের ডিসপিউট দল বিষয়টি যত্নসহকারে পর্যালোচনা করে অফিসিয়াল চ্যানেলে আপনার সাথে যোগাযোগ করবে।`,
  payment_failed: (t) => `আমরা লক্ষ্য করেছি যে${t ? ` লেনদেন ${t}` : ' এই পেমেন্ট'} এর কারণে আপনার ব্যালেন্স থেকে অপ্রত্যাশিতভাবে টাকা কেটে যেতে পারে। আমাদের পেমেন্টস দল বিষয়টি পর্যালোচনা করবে এবং যেকোনো প্রযোজ্য অর্থ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।`,
  refund_request: (t) => `আপনার রিফান্ড অনুরোধ${t ? ` (লেনদেন ${t})` : ''} আমরা গ্রহণ করেছি। সম্পন্ন মার্চেন্ট পেমেন্টের ক্ষেত্রে রিফান্ড মার্চেন্টের নিজস্ব নীতির উপর নির্ভর করে এবং যেকোনো প্রযোজ্য অর্থ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।`,
  duplicate_payment: (t) => `সম্ভাব্য ডাবল পেমেন্ট${t ? ` (লেনদেন ${t})` : ''} এর বিষয়ে আমরা অবগত হয়েছি। আমাদের পেমেন্টস দল রেকর্ড যাচাই করবে এবং যেকোনো প্রযোজ্য অর্থ অফিসিয়াল চ্যানেলে ফেরত দেওয়া হবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।`,
  merchant_settlement_delay: (t) => `আপনার সেটেলমেন্ট${t ? ` (লেনদেন ${t})` : ''} সংক্রান্ত উদ্বেগ আমরা অবগত হয়েছি। আমাদের মার্চেন্ট অপারেশন্স দল ব্যাচের অবস্থা যাচাই করে অফিসিয়াল চ্যানেলে আপনাকে জানাবে।`,
  agent_cash_in_issue: (t) => `আপনার ক্যাশ ইন${t ? ` (লেনদেন ${t})` : ''} সংক্রান্ত বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল রেকর্ড যাচাই করে অফিসিয়াল চ্যানেলে আপনার সাথে যোগাযোগ করবে। অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।`,
  other: () => `এই অনুরোধ পর্যালোচনার জন্য আমাদের আরও কিছু সাধারণ তথ্য প্রয়োজন, যেমন লেনদেন আইডি, পরিমাণ, তারিখ ও চ্যানেল। অনুগ্রহ করে শুধুমাত্র অফিসিয়াল চ্যানেলে তথ্য দিন এবং কারো সাথে আপনার পিন, ওটিপি বা পাসওয়ার্ড শেয়ার করবেন না।`
};

function banglaReply(caseType, txId) {
  return (BN_REPLIES[caseType] || BN_REPLIES.other)(txId);
}

function unique(values) {
  return Array.from(new Set(values.filter((value) => value !== null && value !== undefined && value !== '')));
}

module.exports = {
  analyzeTicket,
  classifyCase,
  selectRelevantTransaction,
  determineEvidence,
  extractAmounts
};
