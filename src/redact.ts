/**
 * Redact common sensitive patterns from text before sending to external AI models.
 * v0.1 — regex-based (India-focused phone / Aadhaar / PAN + email / long digit runs).
 */
export function qshieldRedact(text: string): string {
  if (!text || typeof text !== "string") return text;

  let redacted = text;

  // 1. Indian phone numbers (+91, 91, or 10-digit)
  const phoneRegex = /(\+91|91|0)?[-.\s]?(\d{10})/g;
  redacted = redacted.replace(phoneRegex, "[REDACTED PHONE]");

  // 2. Aadhaar (12 digits, optional separators)
  const aadhaarRegex = /\b(\d{4}[\s.-]?\d{4}[\s.-]?\d{4})\b/g;
  redacted = redacted.replace(aadhaarRegex, "[REDACTED AADHAAR]");

  // 3. PAN (ABCDE1234F) and partial PAN-like
  const panRegex = /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g;
  const panRegex2 = /\b[A-Z]{5}[0-9]{4}\b/g;
  redacted = redacted.replace(panRegex, "[REDACTED PAN]");
  redacted = redacted.replace(panRegex2, "[REDACTED PAN]");

  // 4. Email
  const emailRegex =
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  redacted = redacted.replace(emailRegex, "[REDACTED EMAIL]");

  // 5. Long digit runs (bank-like); keep shorter numbers
  const bankRegex = /\b\d{9,18}\b/g;
  redacted = redacted.replace(bankRegex, (match) => {
    if (match.length > 10) return "[REDACTED ACCOUNT]";
    return match;
  });

  return redacted;
}

/** Alias matching older camelCase style */
export const qShieldRedact = qshieldRedact;
