'use strict';

// Each entry targets a specific secret type.
// Patterns with a capture group (group 1) yield the raw secret value;
// patterns without a capture group use the full match as the secret value.
const PATTERNS = [
  {
    name: 'AWS Access Key ID',
    // AWS IAM access keys always begin with AKIA followed by 16 uppercase alphanumeric chars
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    name: 'AWS Secret Access Key',
    // Context-anchored to the label; captures the 40-char base64-like secret
    regex: /(?:aws[_\-\s]?secret[_\-\s]?(?:access[_\-\s]?)?key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['"]?([A-Za-z0-9\/+=]{40})['"]?/gi,
  },
  {
    name: 'GCP API Key',
    // Google Cloud API keys start with AIza followed by 35 alphanumeric chars
    regex: /\bAIza[0-9A-Za-z]{35}\b/g,
  },
  {
    name: 'GitHub Personal Access Token (classic)',
    // ghp_ = personal, gho_ = OAuth app, ghu_ = user-to-server, ghs_ = server-to-server, ghr_ = refresh
    regex: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g,
  },
  {
    name: 'GitHub Fine-grained Token',
    regex: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
  },
  {
    name: 'Slack Bot/User/App Token',
    // xoxb = bot, xoxp = user, xoxa = app, xoxs = workspace
    regex: /\bxox[baps]-[0-9A-Za-z\-]{10,48}\b/g,
  },
  {
    name: 'Stripe Secret Key',
    regex: /\bsk_(?:live|test)_[A-Za-z0-9]{24,99}\b/g,
  },
  {
    name: 'Stripe Publishable Key',
    regex: /\bpk_(?:live|test)_[A-Za-z0-9]{24,99}\b/g,
  },
  {
    name: 'SendGrid API Key',
    regex: /\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b/g,
  },
  {
    name: 'Twilio Auth Token',
    // Context-anchored to TWILIO_ prefix; captures the 32-char lowercase hex token
    regex: /TWILIO[_A-Z]*\s*[=:]\s*['"]?([a-f0-9]{32})['"]?/gi,
  },
  {
    name: 'Bearer Token (HTTP header)',
    // Captures the token value after the "Bearer " keyword
    regex: /\bBearer\s+([A-Za-z0-9\-._~+\/]+=*)/g,
  },
  {
    name: 'JSON Web Token (JWT)',
    // Three base64url segments; first two always start with "ey" when decoded from JSON
    regex: /\bey[A-Za-z0-9\-_]{10,}\.ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+\/]{10,}\b/g,
  },
  {
    name: 'Generic API Key',
    // Requires a recognizable label; captures the key value (min 16 chars to reduce noise)
    regex: /(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret)\s*[=:]\s*['"]?([A-Za-z0-9\-_]{16,})['"]?/gi,
  },
  {
    name: 'Generic Secret / Token',
    // Context-anchored to common token field names
    regex: /(?:^|[\s,{[])(?:secret|auth_token|access_token|refresh_token|private_token)\s*[=:]\s*['"]?([A-Za-z0-9\-_./+=]{16,})['"]?/gi,
  },
  {
    name: 'Generic Password Field',
    // Context-anchored; captures assigned value (6+ non-whitespace chars)
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]{6,})['"]?/gi,
  },
  {
    name: 'Private Key (PEM header)',
    // Detects the header line of a PEM-encoded private key block
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
  },
  {
    name: 'Database Connection String',
    // Covers MongoDB (plain and SRV), MySQL, PostgreSQL, Redis/Rediss, and generic JDBC
    regex: /(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|redis(?:s)?|jdbc:[\w]+):\/\/[^\s'"<>\n]+/gi,
  },
  {
    name: 'Azure Storage Connection String',
    // Azure Storage SDK format; AccountKey is always 88 base64 chars (512-bit key)
    regex: /DefaultEndpointsProtocol=https?;[^"'\s\n]*AccountKey=[A-Za-z0-9+\/=]{80,90}/gi,
  },
  {
    name: 'Social Security Number (SSN)',
    // US SSN excluding invalid area numbers (000, 666, 900–999) and invalid group/serial ranges
    regex: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g,
  },
  {
    name: 'Credit Card Number',
    // Strict BIN-range patterns: Visa, Mastercard, Amex, Discover (no spaces/dashes)
    regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
  },
];

module.exports = PATTERNS;
