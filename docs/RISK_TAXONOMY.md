# PrivGuard v1 Risk Taxonomy and Sanitization Rules

PrivGuard v1 supports a rule-based risk taxonomy for real-time prompt sanitization and output leakage control.

## Risk score levels

| Score | Level | Action |
|---:|---|---|
| 0-20 | Low | Send sanitized or minimally changed prompt |
| 21-50 | Medium | Generalize personal details before sending |
| 51-80 | High | Rewrite prompt and remove identifying details |
| 81-100 | Critical | Strong rewrite, remove secret values, or block sensitive value |

Outbound prompt rule:

```text
A message can be sent to the third-party LLM only when sanitized_risk_score <= 20.
```

## Risk formula

```text
final_prompt_risk = min(
  100,
  max_entity_risk
  + volume_bonus
  + linkability_bonus
  + sensitive_context_bonus
  + third_party_exposure_bonus
  + user_intent_bonus
)
```

Output risk uses the same taxonomy with stricter final redaction before display.

## Entity taxonomy

| Code | Category | Examples | Base risk | Default action |
|---|---|---|---:|---|
| PERSON_NAME | Private person name | Personal names, doctor names, manager names | 35 | GENERALIZE |
| CONTACT_EMAIL | Email address | Personal/work email | 65 | MASK |
| CONTACT_PHONE | Phone number | Mobile, WhatsApp, landline | 65 | MASK |
| HOME_ADDRESS | Home/private address | Street, apartment, villa | 80 | GENERALIZE |
| EXACT_LOCATION | GPS or precise location | Coordinates, live location, building | 85 | GENERALIZE |
| DOB_AGE | DOB or exact age | Birth date, exact age | 60 | GENERALIZE |
| GOV_ID | Government ID | Passport, national ID, SSN, driving license | 95 | BLOCK_VALUE |
| FINANCIAL_ACCOUNT | Bank/account data | IBAN, account number, routing number | 90 | BLOCK_VALUE |
| PAYMENT_CARD | Card data | Credit/debit card, CVV | 100 | BLOCK_VALUE |
| FINANCIAL_STATUS | Financial status | Salary, debt, tax, loan, credit score | 70 | GENERALIZE |
| CREDENTIAL_SECRET | Password/secret | Password, API key, token, private key | 100 | BLOCK_VALUE |
| HEALTH_DATA | Medical data | Diagnosis, medication, test result, symptoms | 80 | GENERALIZE |
| GENETIC_BIOMETRIC | Genetic/biometric | DNA, fingerprint, Face ID, voiceprint | 90 | GENERALIZE |
| LEGAL_DATA | Legal matter | Lawsuit, case number, divorce, immigration | 80 | GENERALIZE |
| CRIMINAL_DATA | Criminal/offence | Arrest, conviction, police report | 90 | GENERALIZE |
| CHILD_DATA | Children/minors | Child name, school, guardian, minor age | 90 | GENERALIZE |
| PROTECTED_ATTRIBUTE | Protected attribute | Religion, ethnicity, political view, union membership, sex life, sexual orientation | 85 | GENERALIZE |
| EMPLOYMENT_HR | HR/workplace | Employer, manager, performance review, termination | 70 | GENERALIZE |
| EDUCATION_DATA | Education | Student ID, grades, school, records | 70 | GENERALIZE |
| BUSINESS_SECRET | Business secret | Client list, contract, roadmap, pricing | 85 | GENERALIZE |
| SOURCE_CODE_SECRET | Code/config secret | .env values, database URL, API keys | 100 | BLOCK_VALUE |
| PRIVATE_RELATIONSHIP | Private life | Family, partner, divorce, relationship conflict | 55 | GENERALIZE |
| DEVICE_NETWORK_ID | Technical identifier | IP, MAC, device ID, session ID | 65 | MASK |
| QUASI_IDENTIFIER | Indirect identifier | Rare job, small town, exact date, unique event | 45 | GENERALIZE |
| PROMPT_INJECTION_PRIVACY | Privacy-invasive intent | Identify, expose, track, infer private data | 80 | REWRITE |
| OUTPUT_LEAKAGE | Sensitive output | Echoed PII, inferred identity, secret-looking token | 80 | REWRITE |

## Sanitization actions

| Action | Meaning | Example |
|---|---|---|
| MASK | Replace exact value with typed placeholder | `name@example.com` -> `[EMAIL]` |
| GENERALIZE | Replace exact value with broader concept | `diabetes` -> `a medical condition` |
| REMOVE | Delete sensitive value completely | Remove API key body |
| REWRITE | Reconstruct prompt safely | High-risk prompt -> privacy-safe task/context/constraints |
| BLOCK_VALUE | Never send literal value | Passwords, tokens, payment cards, IDs |

## Main rules

### R1: Names

Private names are replaced with generic roles, for example:

```text
Dr. Sarah Khan -> a healthcare provider
my manager John -> my manager
```

### R2: Contact details

Email addresses, phone numbers, and social handles are never forwarded literally.

```text
+971501234567 -> [PHONE]
name@example.com -> [EMAIL]
```

### R3: Exact addresses and locations

Exact home addresses and coordinates are generalized.

```text
Villa 22, Street 15, Al Ain -> a private address in the user's city
24.2075, 55.7447 -> a general location
```

### R4: Government IDs

Government identifiers are critical and blocked.

```text
Passport number X1234567 -> [GOVERNMENT_ID]
```

### R5: Payment cards and financial accounts

Payment card values, CVVs, IBANs, and account numbers are never forwarded literally.

```text
4111 1111 1111 1111 -> [PAYMENT_CARD_REMOVED]
IBAN -> [BANK_ACCOUNT]
```

### R6: Credentials and secrets

Passwords, API keys, tokens, private keys, and database URLs are removed or replaced.

```text
OPENAI_API_KEY=sk-... -> [CODE_SECRET_REMOVED]
```

### R7: Health data

Medical data is generalized.

```text
diabetes -> a medical condition
metformin -> a prescribed medication
Dr. Sarah -> a healthcare provider
```

### R8: Children/minors

Child name, school, exact age, and student identifiers are generalized.

```text
My daughter Lina is 9 at ABC School -> my child, who is a minor, at their school
```

### R9: Protected attributes

Special-category-like data is generalized to preserve discrimination or legal context without exposing exact attribute.

```text
I am Muslim and my boss... -> I have a protected religious characteristic and my employer...
```

### R10: Output control

LLM output is scanned before display. If it contains sensitive spans, they are redacted or generalized before the user sees it.

