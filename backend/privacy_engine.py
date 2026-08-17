"""Privacy detection, risk scoring, and sanitization engine.

This module is intentionally dependency-light so it can run in a backend API,
unit tests, and can be ported to browser-side JavaScript/WASM later.

Design goals:
- Detect sensitive data with transparent rules.
- Compute an explainable 0-100 privacy risk score.
- Prefer semantic generalization/rewrite over raw masking.
- Never keep data beyond the current function call.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
from typing import Callable, Iterable, Literal

Stage = Literal["input", "output"]


@dataclass(frozen=True)
class TaxonomyItem:
    code: str
    label: str
    base_risk: int
    default_action: str
    description: str


@dataclass
class Detection:
    span_id: str = ""
    type: str = ""
    text: str = ""
    start: int = 0
    end: int = 0
    confidence: float = 0.0
    base_risk: int = 0
    action: str = ""
    replacement: str = ""
    context: str = ""


@dataclass
class PrivacyReport:
    original_risk_score: int = 0
    sanitized_risk_score: int = 0
    risk_level_before: str = "Low"
    risk_level_after: str = "Low"
    detected_categories: list[str] | None = None
    actions_applied: list[str] | None = None
    detections: list[dict] | None = None
    sanitized_text: str = ""
    send_to_llm: bool = False
    notes: list[str] | None = None

    def to_dict(self) -> dict:
        return asdict(self)


TAXONOMY: dict[str, TaxonomyItem] = {
    "PERSON_NAME": TaxonomyItem("PERSON_NAME", "Private person name", 35, "GENERALIZE", "Names of private individuals."),
    "CONTACT_EMAIL": TaxonomyItem("CONTACT_EMAIL", "Email address", 65, "MASK", "Personal or work email addresses."),
    "CONTACT_PHONE": TaxonomyItem("CONTACT_PHONE", "Phone number", 65, "MASK", "Mobile, WhatsApp, landline, or similar phone numbers."),
    "HOME_ADDRESS": TaxonomyItem("HOME_ADDRESS", "Home/private address", 80, "GENERALIZE", "Street, apartment, villa, postal address, or similar private addresses."),
    "EXACT_LOCATION": TaxonomyItem("EXACT_LOCATION", "Precise location", 85, "GENERALIZE", "GPS coordinates, live location, or exact building location."),
    "DOB_AGE": TaxonomyItem("DOB_AGE", "Date of birth or exact age", 60, "GENERALIZE", "Birth dates and exact ages."),
    "GOV_ID": TaxonomyItem("GOV_ID", "Government identifier", 95, "BLOCK_VALUE", "Passport, national ID, SSN, driving license, residency ID."),
    "FINANCIAL_ACCOUNT": TaxonomyItem("FINANCIAL_ACCOUNT", "Financial account", 90, "BLOCK_VALUE", "IBAN, bank account, routing number, account number."),
    "PAYMENT_CARD": TaxonomyItem("PAYMENT_CARD", "Payment card", 100, "BLOCK_VALUE", "Credit/debit card numbers, CVV, and card credentials."),
    "FINANCIAL_STATUS": TaxonomyItem("FINANCIAL_STATUS", "Private financial status", 70, "GENERALIZE", "Salary, debt, taxes, loans, credit scores, and private transactions."),
    "CREDENTIAL_SECRET": TaxonomyItem("CREDENTIAL_SECRET", "Credential or secret", 100, "BLOCK_VALUE", "Passwords, API keys, private keys, access tokens, database URLs."),
    "HEALTH_DATA": TaxonomyItem("HEALTH_DATA", "Health data", 80, "GENERALIZE", "Diagnosis, symptoms, medication, treatment, disability, test results."),
    "GENETIC_BIOMETRIC": TaxonomyItem("GENETIC_BIOMETRIC", "Genetic or biometric data", 90, "GENERALIZE", "DNA, genetic reports, fingerprints, face ID, voiceprints."),
    "LEGAL_DATA": TaxonomyItem("LEGAL_DATA", "Legal matter", 80, "GENERALIZE", "Lawsuits, court matters, immigration cases, custody, divorce."),
    "CRIMINAL_DATA": TaxonomyItem("CRIMINAL_DATA", "Criminal/offence data", 90, "GENERALIZE", "Arrests, convictions, police reports, criminal allegations."),
    "CHILD_DATA": TaxonomyItem("CHILD_DATA", "Child/minor data", 90, "GENERALIZE", "Data about children or minors, school, guardians, student identifiers."),
    "PROTECTED_ATTRIBUTE": TaxonomyItem("PROTECTED_ATTRIBUTE", "Protected attribute", 85, "GENERALIZE", "Religion, ethnicity, political opinion, union membership, sex life, sexual orientation."),
    "EMPLOYMENT_HR": TaxonomyItem("EMPLOYMENT_HR", "Employment/HR data", 70, "GENERALIZE", "Employer, manager, HR disputes, performance reviews, salary, employee IDs."),
    "EDUCATION_DATA": TaxonomyItem("EDUCATION_DATA", "Education data", 70, "GENERALIZE", "Student ID, grades, school, university records, disciplinary records."),
    "BUSINESS_SECRET": TaxonomyItem("BUSINESS_SECRET", "Business secret", 85, "GENERALIZE", "Client names, contracts, roadmap, pricing, trade secrets, confidential documents."),
    "SOURCE_CODE_SECRET": TaxonomyItem("SOURCE_CODE_SECRET", "Source code secret", 100, "BLOCK_VALUE", "Secrets in code, .env files, database URLs, endpoints, credentials."),
    "PRIVATE_RELATIONSHIP": TaxonomyItem("PRIVATE_RELATIONSHIP", "Private relationship data", 55, "GENERALIZE", "Family, partner, relationship, divorce, interpersonal conflict details."),
    "DEVICE_NETWORK_ID": TaxonomyItem("DEVICE_NETWORK_ID", "Device/network identifier", 65, "MASK", "IP address, MAC address, session ID, device ID."),
    "QUASI_IDENTIFIER": TaxonomyItem("QUASI_IDENTIFIER", "Quasi-identifier", 45, "GENERALIZE", "Indirect identifiers such as rare job, small town, exact date, unique event."),
    "PROMPT_INJECTION_PRIVACY": TaxonomyItem("PROMPT_INJECTION_PRIVACY", "Privacy-invasive intent", 80, "REWRITE", "Requests to reveal, infer, identify, or expose private information."),
    "OUTPUT_LEAKAGE": TaxonomyItem("OUTPUT_LEAKAGE", "Output leakage", 80, "REWRITE", "LLM output that leaks, reconstructs, or invents sensitive details."),
}

CRITICAL_TYPES = {
    "CREDENTIAL_SECRET",
    "SOURCE_CODE_SECRET",
    "PAYMENT_CARD",
    "GOV_ID",
    "FINANCIAL_ACCOUNT",
}

SENSITIVE_CONTEXT_TYPES = {
    "HEALTH_DATA",
    "GENETIC_BIOMETRIC",
    "LEGAL_DATA",
    "CRIMINAL_DATA",
    "CHILD_DATA",
    "PROTECTED_ATTRIBUTE",
    "EMPLOYMENT_HR",
    "EDUCATION_DATA",
    "FINANCIAL_STATUS",
    "BUSINESS_SECRET",
}

IDENTIFIER_TYPES = {
    "PERSON_NAME",
    "CONTACT_EMAIL",
    "CONTACT_PHONE",
    "HOME_ADDRESS",
    "EXACT_LOCATION",
    "DOB_AGE",
    "GOV_ID",
    "FINANCIAL_ACCOUNT",
    "PAYMENT_CARD",
    "CREDENTIAL_SECRET",
    "DEVICE_NETWORK_ID",
}


def risk_level(score: int) -> str:
    if score <= 20:
        return "Low"
    if score <= 50:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


def _default_replacement(category: str, text: str = "") -> str:
    mapping = {
        "PERSON_NAME": "a person",
        "CONTACT_EMAIL": "[EMAIL]",
        "CONTACT_PHONE": "[PHONE]",
        "HOME_ADDRESS": "a private address",
        "EXACT_LOCATION": "a general location",
        "DOB_AGE": "an age range",
        "GOV_ID": "[GOVERNMENT_ID]",
        "FINANCIAL_ACCOUNT": "[BANK_ACCOUNT]",
        "PAYMENT_CARD": "[PAYMENT_CARD_REMOVED]",
        "FINANCIAL_STATUS": "a private financial detail",
        "CREDENTIAL_SECRET": "[SECRET_REMOVED]",
        "HEALTH_DATA": "a health-related detail",
        "GENETIC_BIOMETRIC": "a biometric or genetic detail",
        "LEGAL_DATA": "a legal matter",
        "CRIMINAL_DATA": "a sensitive legal matter",
        "CHILD_DATA": "a minor",
        "PROTECTED_ATTRIBUTE": "a protected characteristic",
        "EMPLOYMENT_HR": "a workplace matter",
        "EDUCATION_DATA": "an education record",
        "BUSINESS_SECRET": "confidential business information",
        "SOURCE_CODE_SECRET": "[CODE_SECRET_REMOVED]",
        "PRIVATE_RELATIONSHIP": "a private relationship detail",
        "DEVICE_NETWORK_ID": "[TECHNICAL_IDENTIFIER]",
        "QUASI_IDENTIFIER": "a generalized detail",
        "PROMPT_INJECTION_PRIVACY": "a privacy-safe request",
        "OUTPUT_LEAKAGE": "[SENSITIVE_OUTPUT_REMOVED]",
    }
    if category == "HEALTH_DATA":
        lowered = text.lower()
        if any(word in lowered for word in ["medication", "medicine", "metformin", "insulin", "dose", "prescription"]):
            return "a prescribed medication"
        if any(word in lowered for word in ["doctor", "hospital", "clinic", "provider"]):
            return "a healthcare provider"
        return "a medical condition"
    if category == "DOB_AGE" and re.search(r"\b(?:[0-9]|1[0-7])\b", text):
        return "a minor"
    return mapping.get(category, "[SENSITIVE_DATA]")


def _context_window(text: str, start: int, end: int, size: int = 36) -> str:
    left = max(0, start - size)
    right = min(len(text), end + size)
    return text[left:right]


def _make_detection(category: str, match: re.Match[str], text: str, confidence: float = 0.9, replacement: str | None = None) -> Detection:
    item = TAXONOMY[category]
    matched_text = match.group(0)
    return Detection(
        span_id="",
        type=category,
        text=matched_text,
        start=match.start(),
        end=match.end(),
        confidence=confidence,
        base_risk=item.base_risk,
        action=item.default_action,
        replacement=replacement or _default_replacement(category, matched_text),
        context=_context_window(text, match.start(), match.end()),
    )


def _digits_only(value: str) -> str:
    return re.sub(r"\D", "", value)


def _passes_luhn(value: str) -> bool:
    digits = [int(ch) for ch in _digits_only(value)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for idx, digit in enumerate(digits):
        if idx % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


RegexRule = tuple[str, str, float, Callable[[str], bool] | None]


REGEX_RULES: list[RegexRule] = [
    ("CONTACT_EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 0.99, None),
    ("CONTACT_PHONE", r"(?<!\w)(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{2,4}\)?[\s\-.]?){2,5}\d{2,4}(?!\w)", 0.82, None),
    ("PAYMENT_CARD", r"(?<!\w)(?:\d[ -]?){13,19}(?!\w)", 0.95, _passes_luhn),
    ("GOV_ID", r"\b(?:passport|national\s+id|emirates\s+id|ssn|social\s+security|driver'?s?\s+licen[cs]e|residency\s+id)\s*(?:number|no\.?|#|is|:)\s*[A-Z0-9\-]{5,}\b", 0.95, None),
    ("GOV_ID", r"\b784-\d{4}-\d{7}-\d\b", 0.98, None),
    ("FINANCIAL_ACCOUNT", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", 0.9, None),
    ("CREDENTIAL_SECRET", r"\b(?:password|passwd|pwd|api[_\s-]?key|access[_\s-]?token|secret|private[_\s-]?key)\s*[:=]\s*[^\s,;]{6,}\b", 0.98, None),
    ("CREDENTIAL_SECRET", r"\b(?:sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16})\b", 0.98, None),
    ("SOURCE_CODE_SECRET", r"\b(?:DATABASE_URL|DB_PASSWORD|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|JWT_SECRET|PRIVATE_KEY)\s*=\s*[^\n\r]+", 0.98, None),
    ("DEVICE_NETWORK_ID", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.75, None),
    ("DEVICE_NETWORK_ID", r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b", 0.9, None),
    ("EXACT_LOCATION", r"(?<!\w)[+-]?\d{1,2}\.\d{4,}\s*,\s*[+-]?\d{1,3}\.\d{4,}(?!\w)", 0.95, None),
    ("HOME_ADDRESS", r"\b(?:I\s+live\s+(?:at|in)|my\s+address\s+is|home\s+address\s*:)\s+[^.\n]{6,90}", 0.82, None),
    ("DOB_AGE", r"\b(?:date\s+of\s+birth|dob|born\s+on|birthday)\s*(?:is|:)?\s*\d{1,2}[\-/\s](?:\d{1,2}|[A-Za-z]{3,9})[\-/\s]\d{2,4}\b", 0.9, None),
    ("DOB_AGE", r"\b(?:I\s+am|I'm|my\s+(?:son|daughter|child)\s+is|age)\s+\d{1,3}\s*(?:years?\s+old|yo)?\b", 0.75, None),
    ("PERSON_NAME", r"\b(?:my\s+name\s+is|I\s+am|I'm|call\s+me)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b", 0.82, None),
    ("PERSON_NAME", r"\b(?:Dr\.?|Doctor|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b", 0.82, None),
    ("PERSON_NAME", r"\b(?:manager|doctor|teacher|lawyer|daughter|son|wife|husband|partner)\s+(?:named\s+|is\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b", 0.75, None),
    ("CHILD_DATA", r"\b(?:my\s+)?(?:son|daughter|child|kid)\s+(?:named\s+)?[A-Z][a-z]+(?:\s+is)?\s*(?:age\s*)?\d{1,2}?\b", 0.85, None),
    ("EDUCATION_DATA", r"\b(?:student\s+id|school\s+id|university\s+id)\s*(?:is|:)?\s*[A-Z0-9\-]{4,}\b", 0.9, None),
    ("EMPLOYMENT_HR", r"\b(?:employee\s+id)\s*(?:is|:)?\s*[A-Z0-9\-]{4,}\b", 0.9, None),
    ("LEGAL_DATA", r"\b(?:case\s+number|court\s+case|police\s+report)\s*(?:is|:)?\s*[A-Z0-9\-/]{4,}\b", 0.9, None),
]

KEYWORD_RULES: dict[str, list[str]] = {
    "HEALTH_DATA": [
        "diabetes", "hiv", "aids", "adhd", "cancer", "depression", "anxiety", "therapy",
        "diagnosis", "diagnosed", "medication", "medicine", "prescription", "metformin",
        "insulin", "antidepressant", "blood test", "lab result", "hospital", "clinic", "doctor",
        "disability", "pregnancy", "symptoms", "treatment",
    ],
    "GENETIC_BIOMETRIC": ["dna", "genetic", "fingerprint", "face id", "retina", "iris scan", "voiceprint", "biometric"],
    "LEGAL_DATA": ["lawsuit", "divorce", "custody", "immigration case", "court", "lawyer", "legal claim", "case number"],
    "CRIMINAL_DATA": ["arrested", "convicted", "criminal record", "police report", "probation", "offence", "offense"],
    "CHILD_DATA": ["my child", "my son", "my daughter", "minor", "guardian", "school", "kindergarten"],
    "PROTECTED_ATTRIBUTE": [
        "muslim", "christian", "jewish", "hindu", "religion", "ethnicity", "racial",
        "political opinion", "trade union", "union member", "gay", "lesbian", "bisexual",
        "transgender", "sexual orientation", "sex life",
    ],
    "FINANCIAL_STATUS": ["salary", "income", "debt", "loan", "mortgage", "tax", "credit score", "bankruptcy", "transaction"],
    "EMPLOYMENT_HR": ["employer", "manager", "hr", "performance review", "terminated", "fired", "workplace", "employee id"],
    "EDUCATION_DATA": ["student id", "grades", "gpa", "school", "university", "exam result", "disciplinary"],
    "BUSINESS_SECRET": ["confidential", "nda", "trade secret", "client list", "roadmap", "pricing", "contract", "unreleased", "internal project"],
    "PRIVATE_RELATIONSHIP": ["wife", "husband", "girlfriend", "boyfriend", "partner", "family conflict", "relationship", "divorce"],
    "PROMPT_INJECTION_PRIVACY": [
        "find their address", "guess who this is", "identify this person", "reveal their", "expose their",
        "infer their identity", "is this person", "find out if my coworker", "track this person",
    ],
}


def _keyword_pattern(keyword: str) -> re.Pattern[str]:
    escaped = re.escape(keyword)
    escaped = escaped.replace(r"\ ", r"\s+")
    return re.compile(rf"\b{escaped}\b", re.IGNORECASE)


def _iter_regex_detections(text: str) -> Iterable[Detection]:
    for category, pattern, confidence, validator in REGEX_RULES:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0)
            if category == "CONTACT_PHONE":
                digits = _digits_only(value)
                if len(digits) < 7 or len(digits) > 15:
                    continue
            if category == "PAYMENT_CARD" and not _passes_luhn(value):
                continue
            if validator is not None and not validator(value):
                continue
            yield _make_detection(category, match, text, confidence=confidence)


def _iter_keyword_detections(text: str) -> Iterable[Detection]:
    for category, keywords in KEYWORD_RULES.items():
        for keyword in keywords:
            for match in _keyword_pattern(keyword).finditer(text):
                yield _make_detection(category, match, text, confidence=0.72)


def _overlaps(a: Detection, b: Detection) -> bool:
    return max(a.start, b.start) < min(a.end, b.end)


def _dedupe_and_rank(detections: list[Detection]) -> list[Detection]:
    ranked = sorted(
        detections,
        key=lambda d: (d.base_risk, d.end - d.start, d.confidence),
        reverse=True,
    )
    selected: list[Detection] = []
    for det in ranked:
        if all(not _overlaps(det, chosen) for chosen in selected):
            selected.append(det)
    selected.sort(key=lambda d: (d.start, d.end))
    for idx, det in enumerate(selected, start=1):
        det.span_id = f"s{idx}"
    return selected


def detect_sensitive_data(text: str) -> list[Detection]:
    """Return sensitive spans found in text. Stateless and does not retain text after returning."""
    if not text or not text.strip():
        return []
    detections = list(_iter_regex_detections(text)) + list(_iter_keyword_detections(text))
    return _dedupe_and_rank(detections)


def _has_privacy_invasive_intent(text: str) -> bool:
    lowered = text.lower()
    return any(keyword in lowered for keyword in KEYWORD_RULES["PROMPT_INJECTION_PRIVACY"])


def compute_risk_score(text: str, detections: list[Detection], stage: Stage = "input") -> int:
    if not detections:
        if _has_privacy_invasive_intent(text):
            return 80
        return 0

    categories = {d.type for d in detections}
    max_entity_risk = max(d.base_risk for d in detections)
    count = len(detections)

    if count >= 7:
        volume_bonus = 15
    elif count >= 4:
        volume_bonus = 10
    elif count >= 2:
        volume_bonus = 5
    else:
        volume_bonus = 0

    has_identifier = bool(categories & IDENTIFIER_TYPES)
    has_sensitive_context = bool(categories & SENSITIVE_CONTEXT_TYPES)
    quasi_count = sum(1 for d in detections if d.type == "QUASI_IDENTIFIER")
    linkability_bonus = 10 if (has_identifier and has_sensitive_context) or quasi_count >= 3 else 0

    sensitive_context_bonus = 15 if has_sensitive_context else 0
    third_party_exposure_bonus = 10 if stage == "input" else 0

    lowered = text.lower()
    intent_bonus = 0
    if _has_privacy_invasive_intent(text):
        intent_bonus += 20
    if any(word in lowered for word in ["analyze", "summarize", "extract", "infer", "identify", "reveal", "expose"]):
        intent_bonus += 10

    output_bonus = 10 if stage == "output" and max_entity_risk >= 65 else 0

    score = max_entity_risk + volume_bonus + linkability_bonus + sensitive_context_bonus + third_party_exposure_bonus + intent_bonus + output_bonus
    return min(100, max(0, int(score)))


def _replace_spans(text: str, detections: list[Detection]) -> str:
    if not detections:
        return text
    sanitized = text
    for det in sorted(detections, key=lambda d: d.start, reverse=True):
        replacement = det.replacement
        if det.type in CRITICAL_TYPES:
            replacement = _default_replacement(det.type, det.text)
        sanitized = sanitized[: det.start] + replacement + sanitized[det.end :]
    return sanitized


def _build_rewritten_input(text: str, detections: list[Detection]) -> str:
    categories = {d.type for d in detections}
    lowered = text.lower()

    if "email" in lowered:
        task = "Write a polite email to a healthcare provider asking whether a prescribed medication for a chronic medical condition should be adjusted."
    elif "message" in lowered:
        task = "Write a short, respectful message to a trusted neighbor."
    elif "letter" in lowered:
        task = "Write a formal letter about a sensitive matter."
    elif "complain" in lowered or "complaint" in lowered:
        task = "Write a formal complaint letter about a sensitive matter."
    elif "plan" in lowered or "schedule" in lowered:
        task = "Create a general plan or schedule for the user's situation."
    elif "summarize" in lowered:
        task = "Summarize the generalized situation without personal identifiers."
    elif "explain" in lowered:
        task = "Explain the topic using generalized, non-identifying information."
    elif "analyze" in lowered or "review" in lowered:
        task = "Analyze the generalized situation without personal identifiers."
    elif "debug" in lowered or "code" in lowered:
        task = "Help with the technical issue without using any secrets or credentials."
    elif "identify" in lowered or "find" in lowered or "guess" in lowered:
        task = "Explain why inferring private information from indirect details creates privacy risks, and provide privacy-preserving alternatives."
    else:
        task = "Answer the user's request using only generalized, non-identifying context."

    constraints = []
    if "PERSON_NAME" in categories:
        constraints.append("Do not include personal names.")
    if "CONTACT_PHONE" in categories or "CONTACT_EMAIL" in categories:
        constraints.append("Do not include phone numbers or contact details.")
    if "HOME_ADDRESS" in categories or "EXACT_LOCATION" in categories:
        constraints.append("Do not include addresses or precise locations.")
    if "HEALTH_DATA" in categories:
        constraints.append("Do not include specific health conditions or medication details.")
    if "EDUCATION_DATA" in categories:
        constraints.append("Do not include student IDs, school names, or course codes.")
    if "LEGAL_DATA" in categories:
        constraints.append("Do not include case numbers or legal identifiers.")
    if "FINANCIAL_ACCOUNT" in categories or "FINANCIAL_STATUS" in categories:
        constraints.append("Do not include account numbers or exact financial details.")
    if "PAYMENT_CARD" in categories or "CREDENTIAL_SECRET" in categories or "SOURCE_CODE_SECRET" in categories:
        constraints.append("Do not include any secrets, credentials, payment card details, or government IDs.")
    if "BUSINESS_SECRET" in categories:
        constraints.append("Do not include client names, contract values, or confidential business details.")
    if "PROTECTED_ATTRIBUTE" in categories:
        constraints.append("Do not include protected personal characteristics.")
    if "EMPLOYMENT_HR" in categories:
        constraints.append("Do not include employer names, manager names, or employee IDs.")
    if "CHILD_DATA" in categories:
        constraints.append("Do not include the child's name, school, or exact age.")
    if "PRIVATE_RELATIONSHIP" in categories:
        constraints.append("Do not include names or sensitive relationship details.")
    if not constraints:
        constraints.append("Do not include personal identifiers or sensitive details.")

    constraints.append("Use generic roles and generalized descriptions.")

    result = task
    if constraints:
        result += " " + " ".join(f"{c.rstrip('.')}." for c in constraints)
    return result


def _build_safe_output(text: str, detections: list[Detection]) -> str:
    sanitized = _replace_spans(text, detections)
    categories = {d.type for d in detections}
    if categories & CRITICAL_TYPES:
        sanitized = "Sensitive values were removed.\n\n" + sanitized
    return sanitized


def _detected_categories(detections: list[Detection]) -> list[str]:
    return sorted({d.type for d in detections})


def _actions_applied(detections: list[Detection], rewritten: bool) -> list[str]:
    actions = sorted({d.action for d in detections})
    if rewritten and "REWRITE" not in actions:
        actions.append("REWRITE")
    return actions


def analyze_and_sanitize(text: str, stage: Stage = "input") -> dict:
    """Analyze text, sanitize it, and return an explainable privacy report."""
    stage = "output" if stage == "output" else "input"
    raw_text = text or ""
    detections = detect_sensitive_data(raw_text)
    original_risk = compute_risk_score(raw_text, detections, stage=stage)
    categories = {d.type for d in detections}

    rewritten = False
    if stage == "input":
        if original_risk > 50 or categories & CRITICAL_TYPES or "PROMPT_INJECTION_PRIVACY" in categories:
            sanitized = _build_rewritten_input(raw_text, detections)
            rewritten = True
            sanitized_risk = 0
        else:
            sanitized = _replace_spans(raw_text, detections)
            sanitized_risk = original_risk
    else:
        sanitized = _build_safe_output(raw_text, detections)
        rewritten = original_risk > 50
        sanitized_risk = original_risk

    notes: list[str] = []
    if categories & CRITICAL_TYPES:
        notes.append("Critical values were blocked and not forwarded as literal values.")
    if not detections:
        notes.append("No sensitive data detected by the v1 rule set.")

    report = PrivacyReport(
        original_risk_score=original_risk,
        sanitized_risk_score=sanitized_risk,
        risk_level_before=risk_level(original_risk),
        risk_level_after=risk_level(sanitized_risk),
        detected_categories=_detected_categories(detections),
        actions_applied=_actions_applied(detections, rewritten),
        detections=[
            {
                "span_id": d.span_id,
                "type": d.type,
                "text": "[REDACTED]" if d.type in IDENTIFIER_TYPES or d.type in CRITICAL_TYPES else d.text,
                "start": d.start,
                "end": d.end,
                "confidence": d.confidence,
                "base_risk": d.base_risk,
                "action": d.action,
                "replacement": d.replacement,
            }
            for d in detections
        ],
        sanitized_text=sanitized,
        send_to_llm=(stage == "input" and sanitized_risk <= 20),
        notes=notes,
    )
    return report.to_dict()
