# PrivGuard Privacy Design

## Design goal

PrivGuard is designed as a zero-retention privacy gateway for users who want to interact with third-party LLMs without exposing raw sensitive prompts.

The core rule is:

```text
Preserve user intent. Remove or generalize user identity. Store nothing.
```

## Data flow

```text
User browser
  -> browser-side privacy analyzer
  -> browser-side prompt sanitizer
  -> sanitized prompt only
  -> backend relay
  -> third-party LLM provider
  -> backend output privacy scanner
  -> browser final output scanner
  -> user
```

## Zero-retention rules

| Data object | Storage rule |
|---|---|
| Raw prompt | Browser memory only |
| Detected sensitive entities | Browser memory only |
| Entity replacement map | Browser memory only |
| Sanitized prompt | Sent to backend/provider but not stored by this app |
| LLM output | Scanned in memory, not stored |
| Risk report | Displayed to user, not stored by default |
| Logs | No prompt bodies, no output bodies, no detected values |
| Analytics | Aggregate counts only, if enabled later |
| Browser storage | Avoid localStorage and sessionStorage |

## GDPR-oriented principles

This prototype is not a legal compliance product, but its architecture supports GDPR-oriented privacy-by-design patterns:

| GDPR-oriented principle | PrivGuard design choice |
|---|---|
| Data minimization | Send only generalized/sanitized prompts |
| Storage limitation | No database, no content retention |
| Integrity and confidentiality | TLS-ready backend, no body logging, secure headers |
| Privacy by default | Sanitization is automatic |
| Pseudonymization | Typed placeholders and generalized roles |
| Accountability | Local privacy report explains changes |

## Threats addressed

| Threat | Mitigation |
|---|---|
| Prompt leakage to third-party LLM | Raw prompt is sanitized before provider call |
| Accidental secret sharing | Secrets are detected and blocked |
| PII exposure | PII is masked or generalized |
| Sensitive context exposure | Health, legal, financial, child, and protected attributes are generalized |
| Output echo leakage | LLM output is scanned before display |
| Prompt body logging | Backend does not log bodies or store content |

## Production hardening checklist

- Move all input detection into a fully client-side engine or audited local privacy worker.
- Add multilingual PII and sensitive-context detection.
- Add stronger NER models through ONNX Runtime Web or WASM.
- Add enterprise policy profiles.
- Add DPIA and data-processing documentation.
- Add provider contracts and no-training/no-retention provider settings.
- Add security testing, rate limiting, abuse monitoring without prompt bodies.
- Add privacy regression tests for every detector and sanitizer rule.
- Add accessibility testing for the web UI.

