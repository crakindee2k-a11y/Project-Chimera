const SECRET_TERMS = [
  'pin',
  'otp',
  'password',
  'passcode',
  'cvv',
  'cvc',
  'full card number',
  'card number',
  'পিন',
  'ওটিপি',
  'পাসওয়ার্ড',
  'পাসওয়ার্ড'
];

const PROMISE_PATTERNS = [
  /\bwe\s+will\s+(refund|reverse|unblock|recover|return)\b/i,
  /\bguarantee(?:d)?\s+(refund|reversal|recovery|unblock)\b/i,
  /\b(refund|reversal|recovery|unblock)\s+is\s+confirmed\b/i,
  /\byour\s+(money|account|amount)\s+will\s+be\s+(refunded|reversed|recovered|unblocked)\b/i
];

const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?previous\s+instructions/i,
  /disregard\s+(all\s+)?previous\s+instructions/i,
  /system\s+prompt/i,
  /developer\s+message/i,
  /return\s+only\s+json/i,
  /override\s+policy/i,
  /forget\s+your\s+rules/i,
  /act\s+as\s+/i
];

const FRAUD_PATTERNS = [
  /\b(phishing|fraud|fraudulent|scam|hacked|hack|stolen|unauthorized|impersonat(?:e|ion)|fake\s+(?:call|link|sms|support|agent)|suspicious\s+link|social\s+engineering)\b/i,
  /\b(otp|pin|password|passcode)\b.*\b(shared|gave|asked|requested|told|sent)\b/i,
  /\b(shared|gave|sent)\b.*\b(otp|pin|password|passcode)\b/i,
  /\b(account\s+blocked|verify\s+account|prize|lottery)\b.*\b(link|otp|pin|password)\b/i,
  // Bangla: standalone fraud terms, OR a credential word co-occurring with a suspicious/asked context.
  // Bare "পিন"/"ওটিপি" alone is NOT fraud — avoids false-positive criticals on benign Bangla complaints.
  /(ফিশিং|প্রতারণা|প্রতারক|ভুয়া\s*(?:কল|এজেন্ট|লিংক|এসএমএস|সাপোর্ট))/,
  /(ওটিপি|পিন|পাসওয়ার্ড).*(চাইল|চেয়েছে|চেয়েছিল|শেয়ার|দিয়েছি|দিয়েছেন|জানতে|হ্যাক|ভুয়া)/,
  /(চাইল|চেয়েছে|শেয়ার|হ্যাক|ভুয়া|সন্দেহ).*(ওটিপি|পিন|পাসওয়ার্ড)/
];

const BN_FRAUD_REPLY = 'এই অভিযোগটি সম্ভাব্য প্রতারণা বা সোশ্যাল ইঞ্জিনিয়ারিং হিসেবে চিহ্নিত করা হয়েছে। কারো সাথে আপনার পিন, ওটিপি, পাসওয়ার্ড বা সম্পূর্ণ কার্ড নম্বর শেয়ার করবেন না, অজানা লিংকে ক্লিক করবেন না এবং শুধুমাত্র অফিসিয়াল চ্যানেল ব্যবহার করুন। আমাদের ফ্রড রিস্ক দল বিষয়টি পর্যালোচনা করবে।';

function resolveLanguage(input) {
  if (input && input.language === 'bn') return 'bn';
  if (/[ঀ-৿]/.test(String(input?.complaint || ''))) return 'bn';
  return 'en';
}

function hasPromptInjection(text) {
  return INJECTION_PATTERNS.some((pattern) => pattern.test(text || ''));
}

function hasFraudRisk(text) {
  return FRAUD_PATTERNS.some((pattern) => pattern.test(text || ''));
}

function sanitizeReply(reply, language) {
  let safe = String(reply || '').replace(/\s+/g, ' ').trim();

  for (const pattern of PROMISE_PATTERNS) {
    safe = safe.replace(pattern, 'our team will review eligibility through official channels');
  }

  // Allow defensive warnings like "do not share your PIN or OTP". Block requests for secrets.
  const asksForSecret = new RegExp(
    `\\b(share|send|provide|tell|give|confirm|enter|submit)\\b.{0,50}\\b(${SECRET_TERMS.map(escapeRegex).join('|')})\\b`,
    'i'
  );
  if (asksForSecret.test(safe) && !/do\s+not\s+share|never\s+share|শেয়ার\s+করবেন\s+না/i.test(safe)) {
    safe = language === 'bn'
      ? 'অনুগ্রহ করে শুধুমাত্র অফিসিয়াল চ্যানেল ব্যবহার করুন এবং লেনদেন আইডি, পরিমাণ ও সময়ের মতো সাধারণ তথ্য দিন। কারো সাথে আপনার পিন, ওটিপি, পাসওয়ার্ড বা সম্পূর্ণ কার্ড নম্বর শেয়ার করবেন না।'
      : 'Please use only official support channels and share non-sensitive details such as transaction ID, amount, and time. Never share your PIN, OTP, password, or full card number.';
  }

  const hasOfficial = language === 'bn' ? /official|অফিসিয়াল/i.test(safe) : /official/i.test(safe);
  if (!hasOfficial) {
    safe += language === 'bn' ? ' অনুগ্রহ করে শুধুমাত্র অফিসিয়াল চ্যানেল ব্যবহার করুন।' : ' Please use only official support channels.';
  }
  return safe;
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function applySafety(output, input) {
  const complaint = input?.complaint || '';
  const language = resolveLanguage(input);
  const reasonCodes = new Set(output.reason_codes || []);

  if (hasPromptInjection(complaint)) {
    reasonCodes.add('prompt_injection_ignored');
  }

  if (hasFraudRisk(complaint)) {
    output.case_type = 'phishing_or_social_engineering';
    output.department = 'fraud_risk';
    output.severity = 'critical';
    output.evidence_verdict = 'insufficient_data';
    output.human_review_required = true;
    reasonCodes.add('fraud_risk');
    output.customer_reply = language === 'bn'
      ? BN_FRAUD_REPLY
      : 'We have flagged this as a possible fraud or social-engineering concern. Do not share your PIN, OTP, password, or full card number with anyone, do not click unknown links, and use only official support channels. Our fraud risk team will review the case.';
    output.recommended_next_action = 'Escalate immediately to fraud risk. Preserve complaint details, check account activity, and contact the customer only through official channels.';
  }

  output.customer_reply = sanitizeReply(output.customer_reply, language);
  output.reason_codes = Array.from(reasonCodes);
  return output;
}

module.exports = {
  hasPromptInjection,
  hasFraudRisk,
  sanitizeReply,
  applySafety,
  resolveLanguage
};
