(function () {
  "use strict";

  const TAXONOMY = {
    PERSON_NAME: { baseRisk: 35, action: "GENERALIZE", label: "Private person name" },
    CONTACT_EMAIL: { baseRisk: 65, action: "MASK", label: "Email address" },
    CONTACT_PHONE: { baseRisk: 65, action: "MASK", label: "Phone number" },
    HOME_ADDRESS: { baseRisk: 80, action: "GENERALIZE", label: "Home/private address" },
    EXACT_LOCATION: { baseRisk: 85, action: "GENERALIZE", label: "Precise location" },
    DOB_AGE: { baseRisk: 60, action: "GENERALIZE", label: "Date of birth or exact age" },
    GOV_ID: { baseRisk: 95, action: "BLOCK_VALUE", label: "Government identifier" },
    FINANCIAL_ACCOUNT: { baseRisk: 90, action: "BLOCK_VALUE", label: "Financial account" },
    PAYMENT_CARD: { baseRisk: 100, action: "BLOCK_VALUE", label: "Payment card" },
    FINANCIAL_STATUS: { baseRisk: 70, action: "GENERALIZE", label: "Private financial status" },
    CREDENTIAL_SECRET: { baseRisk: 100, action: "BLOCK_VALUE", label: "Credential or secret" },
    HEALTH_DATA: { baseRisk: 80, action: "GENERALIZE", label: "Health data" },
    GENETIC_BIOMETRIC: { baseRisk: 90, action: "GENERALIZE", label: "Genetic or biometric data" },
    LEGAL_DATA: { baseRisk: 80, action: "GENERALIZE", label: "Legal matter" },
    CRIMINAL_DATA: { baseRisk: 90, action: "GENERALIZE", label: "Criminal/offence data" },
    CHILD_DATA: { baseRisk: 90, action: "GENERALIZE", label: "Child/minor data" },
    PROTECTED_ATTRIBUTE: { baseRisk: 85, action: "GENERALIZE", label: "Protected attribute" },
    EMPLOYMENT_HR: { baseRisk: 70, action: "GENERALIZE", label: "Employment/HR data" },
    EDUCATION_DATA: { baseRisk: 70, action: "GENERALIZE", label: "Education data" },
    BUSINESS_SECRET: { baseRisk: 85, action: "GENERALIZE", label: "Business secret" },
    SOURCE_CODE_SECRET: { baseRisk: 100, action: "BLOCK_VALUE", label: "Source code secret" },
    PRIVATE_RELATIONSHIP: { baseRisk: 55, action: "GENERALIZE", label: "Private relationship" },
    DEVICE_NETWORK_ID: { baseRisk: 65, action: "MASK", label: "Device/network identifier" },
    QUASI_IDENTIFIER: { baseRisk: 45, action: "GENERALIZE", label: "Quasi-identifier" },
    PROMPT_INJECTION_PRIVACY: { baseRisk: 80, action: "REWRITE", label: "Privacy-invasive intent" },
    OUTPUT_LEAKAGE: { baseRisk: 80, action: "REWRITE", label: "Output leakage" }
  };

  const CRITICAL_TYPES = new Set([
    "CREDENTIAL_SECRET",
    "SOURCE_CODE_SECRET",
    "PAYMENT_CARD",
    "GOV_ID",
    "FINANCIAL_ACCOUNT"
  ]);

  const SENSITIVE_CONTEXT_TYPES = new Set([
    "HEALTH_DATA",
    "GENETIC_BIOMETRIC",
    "LEGAL_DATA",
    "CRIMINAL_DATA",
    "CHILD_DATA",
    "PROTECTED_ATTRIBUTE",
    "EMPLOYMENT_HR",
    "EDUCATION_DATA",
    "FINANCIAL_STATUS",
    "BUSINESS_SECRET"
  ]);

  const IDENTIFIER_TYPES = new Set([
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
    "DEVICE_NETWORK_ID"
  ]);

  const REGEX_RULES = [
    ["CONTACT_EMAIL", /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/gi, 0.99, null],
    ["CONTACT_PHONE", /(?<!\w)(?:\+?\d{1,3}[\s\-.]?)?(?:\(?\d{2,4}\)?[\s\-.]?){2,5}\d{2,4}(?!\w)/gi, 0.82, "phone"],
    ["PAYMENT_CARD", /(?<!\w)(?:\d[ -]?){13,19}(?!\w)/gi, 0.95, "luhn"],
    ["GOV_ID", /\b(?:passport|national\s+id|emirates\s+id|ssn|social\s+security|driver'?s?\s+licen[cs]e|residency\s+id)\s*(?:number|no\.?|#|is|:)\s*[A-Z0-9\-]{5,}\b/gi, 0.95, null],
    ["GOV_ID", /\b784-\d{4}-\d{7}-\d\b/gi, 0.98, null],
    ["FINANCIAL_ACCOUNT", /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/g, 0.9, null],
    ["CREDENTIAL_SECRET", /\b(?:password|passwd|pwd|api[_\s-]?key|access[_\s-]?token|secret|private[_\s-]?key)\s*[:=]\s*[^\s,;]{6,}\b/gi, 0.98, null],
    ["CREDENTIAL_SECRET", /\b(?:sk-[A-Za-z0-9_\-]{20,}|ghp_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9\-]{20,}|AKIA[0-9A-Z]{16})\b/g, 0.98, null],
    ["SOURCE_CODE_SECRET", /\b(?:DATABASE_URL|DB_PASSWORD|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|JWT_SECRET|PRIVATE_KEY)\s*=\s*[^\n\r]+/g, 0.98, null],
    ["DEVICE_NETWORK_ID", /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 0.75, null],
    ["DEVICE_NETWORK_ID", /\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b/g, 0.9, null],
    ["EXACT_LOCATION", /(?<!\w)[+-]?\d{1,2}\.\d{4,}\s*,\s*[+-]?\d{1,3}\.\d{4,}(?!\w)/g, 0.95, null],
    ["HOME_ADDRESS", /\b(?:I\s+live\s+(?:at|in)|my\s+address\s+is|home\s+address\s*:)\s+[^.\n]{6,90}/gi, 0.82, null],
    ["DOB_AGE", /\b(?:date\s+of\s+birth|dob|born\s+on|birthday)\s*(?:is|:)?\s*\d{1,2}[\-/\s](?:\d{1,2}|[A-Za-z]{3,9})[\-/\s]\d{2,4}\b/gi, 0.9, null],
    ["DOB_AGE", /\b(?:I\s+am|I'm|my\s+(?:son|daughter|child)\s+is|age)\s+\d{1,3}\s*(?:years?\s+old|yo)?\b/gi, 0.75, null],
    ["PERSON_NAME", /\b(?:my\s+name\s+is|I\s+am|I'm|call\s+me)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b/g, 0.82, null],
    ["PERSON_NAME", /\b(?:Dr\.?|Doctor|Mr\.?|Mrs\.?|Ms\.?|Prof\.?)\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\b/g, 0.82, null],
    ["PERSON_NAME", /\b(?:manager|doctor|teacher|lawyer|daughter|son|wife|husband|partner)\s+(?:named\s+|is\s+)?[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b/g, 0.75, null],
    ["CHILD_DATA", /\b(?:my\s+)?(?:son|daughter|child|kid)\s+(?:named\s+)?[A-Z][a-z]+(?:\s+is)?\s*(?:age\s*)?\d{1,2}?\b/gi, 0.85, null],
    ["EDUCATION_DATA", /\b(?:student\s+id|school\s+id|university\s+id)\s*(?:is|:)?\s*[A-Z0-9\-]{4,}\b/gi, 0.9, null],
    ["EMPLOYMENT_HR", /\b(?:employee\s+id)\s*(?:is|:)?\s*[A-Z0-9\-]{4,}\b/gi, 0.9, null],
    ["LEGAL_DATA", /\b(?:case\s+number|court\s+case|police\s+report)\s*(?:is|:)?\s*[A-Z0-9\-/]{4,}\b/gi, 0.9, null]
  ];

  const KEYWORD_RULES = {
    HEALTH_DATA: [
      "diabetes", "hiv", "aids", "adhd", "cancer", "depression", "anxiety", "therapy",
      "diagnosis", "diagnosed", "medication", "medicine", "prescription", "metformin",
      "insulin", "antidepressant", "blood test", "lab result", "hospital", "clinic", "doctor",
      "disability", "pregnancy", "symptoms", "treatment"
    ],
    GENETIC_BIOMETRIC: ["dna", "genetic", "fingerprint", "face id", "retina", "iris scan", "voiceprint", "biometric"],
    LEGAL_DATA: ["lawsuit", "divorce", "custody", "immigration case", "court", "lawyer", "legal claim", "case number"],
    CRIMINAL_DATA: ["arrested", "convicted", "criminal record", "police report", "probation", "offence", "offense"],
    CHILD_DATA: ["my child", "my son", "my daughter", "minor", "guardian", "school", "kindergarten"],
    PROTECTED_ATTRIBUTE: [
      "muslim", "christian", "jewish", "hindu", "religion", "ethnicity", "racial",
      "political opinion", "trade union", "union member", "gay", "lesbian", "bisexual",
      "transgender", "sexual orientation", "sex life"
    ],
    FINANCIAL_STATUS: ["salary", "income", "debt", "loan", "mortgage", "tax", "credit score", "bankruptcy", "transaction"],
    EMPLOYMENT_HR: ["employer", "manager", "hr", "performance review", "terminated", "fired", "workplace", "employee id"],
    EDUCATION_DATA: ["student id", "grades", "gpa", "school", "university", "exam result", "disciplinary"],
    BUSINESS_SECRET: ["confidential", "nda", "trade secret", "client list", "roadmap", "pricing", "contract", "unreleased", "internal project"],
    PRIVATE_RELATIONSHIP: ["wife", "husband", "girlfriend", "boyfriend", "partner", "family conflict", "relationship", "divorce"],
    PROMPT_INJECTION_PRIVACY: [
      "find their address", "guess who this is", "identify this person", "reveal their", "expose their",
      "infer their identity", "is this person", "find out if my coworker", "track this person"
    ]
  };

  function digitsOnly(value) {
    return (value || "").replace(/\D/g, "");
  }

  function passesLuhn(value) {
    const digits = digitsOnly(value).split("").map(Number);
    if (digits.length < 13 || digits.length > 19) return false;
    let checksum = 0;
    const parity = digits.length % 2;
    for (let i = 0; i < digits.length; i += 1) {
      let digit = digits[i];
      if (i % 2 === parity) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      checksum += digit;
    }
    return checksum % 10 === 0;
  }

  function replacementFor(category, text) {
    const lowered = (text || "").toLowerCase();
    if (category === "HEALTH_DATA") {
      if (["medication", "medicine", "metformin", "insulin", "dose", "prescription"].some((w) => lowered.includes(w))) {
        return "a prescribed medication";
      }
      if (["doctor", "hospital", "clinic", "provider"].some((w) => lowered.includes(w))) {
        return "a healthcare provider";
      }
      return "a medical condition";
    }
    const mapping = {
      PERSON_NAME: "a person",
      CONTACT_EMAIL: "[EMAIL]",
      CONTACT_PHONE: "[PHONE]",
      HOME_ADDRESS: "a private address",
      EXACT_LOCATION: "a general location",
      DOB_AGE: "an age range",
      GOV_ID: "[GOVERNMENT_ID]",
      FINANCIAL_ACCOUNT: "[BANK_ACCOUNT]",
      PAYMENT_CARD: "[PAYMENT_CARD_REMOVED]",
      FINANCIAL_STATUS: "a private financial detail",
      CREDENTIAL_SECRET: "[SECRET_REMOVED]",
      GENETIC_BIOMETRIC: "a biometric or genetic detail",
      LEGAL_DATA: "a legal matter",
      CRIMINAL_DATA: "a sensitive legal matter",
      CHILD_DATA: "a minor",
      PROTECTED_ATTRIBUTE: "a protected characteristic",
      EMPLOYMENT_HR: "a workplace matter",
      EDUCATION_DATA: "an education record",
      BUSINESS_SECRET: "confidential business information",
      SOURCE_CODE_SECRET: "[CODE_SECRET_REMOVED]",
      PRIVATE_RELATIONSHIP: "a private relationship detail",
      DEVICE_NETWORK_ID: "[TECHNICAL_IDENTIFIER]",
      QUASI_IDENTIFIER: "a generalized detail",
      PROMPT_INJECTION_PRIVACY: "a privacy-safe request",
      OUTPUT_LEAKAGE: "[SENSITIVE_OUTPUT_REMOVED]"
    };
    return mapping[category] || "[SENSITIVE_DATA]";
  }

  function makeDetection(category, matchText, start, end, confidence, fullText) {
    const item = TAXONOMY[category];
    return {
      span_id: "",
      type: category,
      text: matchText,
      start,
      end,
      confidence,
      base_risk: item.baseRisk,
      action: item.action,
      replacement: replacementFor(category, matchText),
      context: fullText.slice(Math.max(0, start - 36), Math.min(fullText.length, end + 36))
    };
  }

  function escapeRegExp(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function keywordRegex(keyword) {
    const pattern = escapeRegExp(keyword).replace(/\\ /g, "\\s+");
    return new RegExp(`\\b${pattern}\\b`, "gi");
  }

  function overlaps(a, b) {
    return Math.max(a.start, b.start) < Math.min(a.end, b.end);
  }

  function dedupeAndRank(detections) {
    const ranked = detections.slice().sort((a, b) => {
      const ar = a.base_risk * 1000 + (a.end - a.start) * 10 + a.confidence;
      const br = b.base_risk * 1000 + (b.end - b.start) * 10 + b.confidence;
      return br - ar;
    });
    const selected = [];
    for (const det of ranked) {
      if (selected.every((existing) => !overlaps(det, existing))) selected.push(det);
    }
    selected.sort((a, b) => a.start - b.start || a.end - b.end);
    selected.forEach((det, index) => {
      det.span_id = `s${index + 1}`;
    });
    return selected;
  }

  function detectSensitiveData(text) {
    if (!text || !text.trim()) return [];
    const detections = [];
    for (const [category, regex, confidence, validator] of REGEX_RULES) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(text)) !== null) {
        const value = match[0];
        if (validator === "phone") {
          const digits = digitsOnly(value);
          if (digits.length < 7 || digits.length > 15) continue;
        }
        if (validator === "luhn" && !passesLuhn(value)) continue;
        detections.push(makeDetection(category, value, match.index, match.index + value.length, confidence, text));
      }
    }
    for (const [category, keywords] of Object.entries(KEYWORD_RULES)) {
      for (const keyword of keywords) {
        const regex = keywordRegex(keyword);
        let match;
        while ((match = regex.exec(text)) !== null) {
          const value = match[0];
          detections.push(makeDetection(category, value, match.index, match.index + value.length, 0.72, text));
        }
      }
    }
    return dedupeAndRank(detections);
  }

  function hasPrivacyInvasiveIntent(text) {
    const lowered = (text || "").toLowerCase();
    return KEYWORD_RULES.PROMPT_INJECTION_PRIVACY.some((keyword) => lowered.includes(keyword));
  }

  function computeRiskScore(text, detections, stage) {
    if (!detections.length) return hasPrivacyInvasiveIntent(text) ? 80 : 0;
    const categories = new Set(detections.map((d) => d.type));
    const maxEntityRisk = Math.max(...detections.map((d) => d.base_risk));
    const count = detections.length;
    const volumeBonus = count >= 7 ? 15 : count >= 4 ? 10 : count >= 2 ? 5 : 0;
    const hasIdentifier = [...categories].some((cat) => IDENTIFIER_TYPES.has(cat));
    const hasSensitiveContext = [...categories].some((cat) => SENSITIVE_CONTEXT_TYPES.has(cat));
    const quasiCount = detections.filter((d) => d.type === "QUASI_IDENTIFIER").length;
    const linkabilityBonus = (hasIdentifier && hasSensitiveContext) || quasiCount >= 3 ? 10 : 0;
    const sensitiveContextBonus = hasSensitiveContext ? 15 : 0;
    const thirdPartyExposureBonus = stage === "input" ? 10 : 0;
    const lowered = (text || "").toLowerCase();
    let intentBonus = hasPrivacyInvasiveIntent(text) ? 20 : 0;
    if (["analyze", "summarize", "extract", "infer", "identify", "reveal", "expose"].some((w) => lowered.includes(w))) {
      intentBonus += 10;
    }
    const outputBonus = stage === "output" && maxEntityRisk >= 65 ? 10 : 0;
    return Math.min(100, maxEntityRisk + volumeBonus + linkabilityBonus + sensitiveContextBonus + thirdPartyExposureBonus + intentBonus + outputBonus);
  }

  function riskLevel(score) {
    if (score <= 20) return "Low";
    if (score <= 50) return "Medium";
    if (score <= 80) return "High";
    return "Critical";
  }

  function replaceSpans(text, detections) {
    let sanitized = text;
    const ordered = detections.slice().sort((a, b) => b.start - a.start);
    for (const det of ordered) {
      const replacement = CRITICAL_TYPES.has(det.type) ? replacementFor(det.type, det.text) : det.replacement;
      sanitized = sanitized.slice(0, det.start) + replacement + sanitized.slice(det.end);
    }
    return sanitized;
  }

  function inferUserTask(text) {
    const lowered = (text || "").toLowerCase();
    if (["write", "draft", "compose"].some((w) => lowered.includes(w))) {
      if (lowered.includes("email")) return "Write a privacy-safe email.";
      if (lowered.includes("message")) return "Write a privacy-safe message.";
      if (lowered.includes("letter")) return "Write a privacy-safe letter.";
      return "Write a privacy-safe text.";
    }
    if (lowered.includes("summarize")) return "Summarize the generalized situation without personal identifiers.";
    if (lowered.includes("explain")) return "Explain the topic using generalized, non-identifying information.";
    if (lowered.includes("analyze") || lowered.includes("review")) return "Analyze the generalized situation without personal identifiers.";
    if (lowered.includes("debug") || lowered.includes("code")) return "Help with the technical issue without using any secrets or credentials.";
    if (lowered.includes("advice") || lowered.includes("help")) return "Provide general guidance using privacy-preserving wording.";
    return "Answer the user's request using only generalized, non-identifying context.";
  }

  function contextSummary(categories) {
    const lines = [];
    if (categories.has("HEALTH_DATA")) lines.push("The request involves a health-related situation.");
    if (categories.has("CHILD_DATA")) lines.push("The request involves a minor, so child identifiers must be removed.");
    if (categories.has("LEGAL_DATA") || categories.has("CRIMINAL_DATA")) lines.push("The request involves a sensitive legal matter.");
    if (categories.has("FINANCIAL_STATUS") || categories.has("FINANCIAL_ACCOUNT") || categories.has("PAYMENT_CARD")) lines.push("The request involves private financial information.");
    if (categories.has("PROTECTED_ATTRIBUTE")) lines.push("The request involves a protected personal characteristic.");
    if (categories.has("EMPLOYMENT_HR")) lines.push("The request involves a workplace or HR matter.");
    if (categories.has("EDUCATION_DATA")) lines.push("The request involves education-related information.");
    if (categories.has("BUSINESS_SECRET")) lines.push("The request involves confidential business information.");
    if (categories.has("CREDENTIAL_SECRET") || categories.has("SOURCE_CODE_SECRET")) lines.push("The request involves secrets or credentials that must not be shared.");
    if (categories.has("PROMPT_INJECTION_PRIVACY")) lines.push("The request may ask for private information about another person and must be made privacy-safe.");
    if (!lines.length) lines.push("The request contains private identifiers that were generalized.");
    return lines;
  }

  function buildRewrittenInput(text, detections) {
    const categories = new Set(detections.map((d) => d.type));
    const constraints = [
      "Do not include names, contact details, account numbers, government IDs, secrets, exact addresses, or precise locations.",
      "Use generic roles and generalized descriptions.",
      "Do not infer or reveal private information about any person.",
      "Provide a helpful answer while preserving privacy."
    ];
    if ([...categories].some((cat) => CRITICAL_TYPES.has(cat))) {
      constraints.unshift("Do not include any secret value, credential, payment card, bank account, or government identifier.");
    }
    return [
      "User task:",
      inferUserTask(text),
      "",
      "Privacy-safe context:",
      ...contextSummary(categories).map((line) => `- ${line}`),
      "",
      "Constraints:",
      ...constraints.map((line) => `- ${line}`)
    ].join("\n");
  }

  function sanitizeOutput(text, detections) {
    let sanitized = replaceSpans(text, detections);
    if (detections.some((d) => CRITICAL_TYPES.has(d.type))) {
      sanitized = `Sensitive values were removed.\n\n${sanitized}`;
    }
    return sanitized;
  }

  function redactDetectionsForDisplay(detections) {
    return detections.map((d) => ({
      span_id: d.span_id,
      type: d.type,
      text: IDENTIFIER_TYPES.has(d.type) || CRITICAL_TYPES.has(d.type) ? "[REDACTED]" : d.text,
      start: d.start,
      end: d.end,
      confidence: d.confidence,
      base_risk: d.base_risk,
      action: d.action,
      replacement: d.replacement
    }));
  }

  function analyzeAndSanitize(text, stage = "input") {
    const normalizedStage = stage === "output" ? "output" : "input";
    const detections = detectSensitiveData(text || "");
    const originalRisk = computeRiskScore(text || "", detections, normalizedStage);
    const categories = new Set(detections.map((d) => d.type));
    let rewritten = false;
    let sanitized;

    if (normalizedStage === "input") {
      if (originalRisk > 50 || [...categories].some((cat) => CRITICAL_TYPES.has(cat)) || categories.has("PROMPT_INJECTION_PRIVACY")) {
        sanitized = buildRewrittenInput(text || "", detections);
        rewritten = true;
      } else {
        sanitized = replaceSpans(text || "", detections);
      }
    } else {
      sanitized = sanitizeOutput(text || "", detections);
      rewritten = originalRisk > 50;
    }

    let sanitizedDetections = detectSensitiveData(sanitized);
    let sanitizedRisk = computeRiskScore(sanitized, sanitizedDetections, normalizedStage);
    const notes = [];

    if (normalizedStage === "input" && sanitizedRisk > 20) {
      sanitized = [
        "Provide a helpful, privacy-preserving answer to the user's generalized request.",
        "Do not include personal identifiers, secrets, credentials, government IDs, payment details, addresses, phone numbers, emails, or exact health/legal/financial details.",
        "Use generic placeholders and general guidance only."
      ].join("\n");
      rewritten = true;
      sanitizedDetections = detectSensitiveData(sanitized);
      sanitizedRisk = computeRiskScore(sanitized, sanitizedDetections, normalizedStage);
      notes.push("Fallback privacy prompt was used because the sanitized prompt still exceeded the low-risk threshold.");
    }

    if ([...categories].some((cat) => CRITICAL_TYPES.has(cat))) {
      notes.push("Critical values were blocked and not forwarded as literal values.");
    }
    if (!detections.length) {
      notes.push("No sensitive data detected by the v1 rule set.");
    }

    const actions = [...new Set(detections.map((d) => d.action))].sort();
    if (rewritten && !actions.includes("REWRITE")) actions.push("REWRITE");

    return {
      original_risk_score: originalRisk,
      sanitized_risk_score: sanitizedRisk,
      risk_level_before: riskLevel(originalRisk),
      risk_level_after: riskLevel(sanitizedRisk),
      detected_categories: [...categories].sort(),
      actions_applied: actions,
      detections: redactDetectionsForDisplay(detections),
      sanitized_text: sanitized,
      send_to_llm: normalizedStage === "input" && sanitizedRisk <= 20,
      notes
    };
  }

  window.PrivacyEngine = {
    TAXONOMY,
    detectSensitiveData,
    analyzeAndSanitize,
    riskLevel
  };
}());
