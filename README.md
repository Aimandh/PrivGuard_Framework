# PrivGuard Prototype

PrivGuard is a zero-retention web app prototype that helps users sanitize prompts before sending them to third-party LLMs. It detects sensitive data, computes a privacy risk score, rewrites/generalizes prompts, sends only sanitized prompts to an LLM provider, and scans the LLM output before displaying it.

This prototype implements a dual-stage privacy gateway:

1. **Input privacy control**: detect sensitive entities, score risk, sanitize/rewrite prompt.
2. **LLM relay**: send only the sanitized prompt to a third-party provider.
3. **Output privacy control**: scan the LLM response, redact/rewrite risky content, return a safe response.

The default provider is a mock LLM, so you can run the project without any API key.

---

## Features

- Web chat interface
- Local browser-side detection and sanitization before sending to backend
- Backend defense-in-depth privacy guard
- Risk score from 0 to 100
- Risk levels: Low, Medium, High, Critical
- Prompt rewriting/generalization instead of simple masking only
- Output leakage detection and redaction
- User-selectable provider target: Mock, llama.cpp, Ollama, ChatGPT, Claude, Gemini, Kimi, Qwen, Mistral, DeepSeek, or custom OpenAI-compatible
- Zero database and zero prompt retention by default
- No raw prompt logging
- Optional OpenAI-compatible third-party LLM relay
- GDPR-oriented privacy-by-design documentation

---

## Project structure

```text
privguard-prototype/
  backend/
    app.py                 FastAPI app and API routes
    llm_client.py          Mock and OpenAI-compatible LLM provider client
    privacy_engine.py      Backend detector, risk scorer, sanitizer
    requirements.txt       Python dependencies
    tests/                 Lightweight tests
  frontend/
    index.html             Web UI
    app.js                 UI logic and backend calls
    privacy-engine.js      Browser-side privacy engine
    styles.css             UI styles
  docs/
    PRIVACY_DESIGN.md      Zero-retention and GDPR-oriented design notes
    RISK_TAXONOMY.md       Risk taxonomy and sanitization rules
  .env.example             Provider configuration template
  docker-compose.yml       Optional container runner
  README.md
```

---

## Quick start

### 1. Create a Python environment

```bash
cd privguard-prototype
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
cd privguard-prototype
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 3. Run the app

```bash
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000
```

By default, the app uses `LLM_PROVIDER=mock`, so no third-party API call is made.

---

## Optional: connect a third-party LLM provider

Copy the environment file:

```bash
cp .env.example .env
```

Set the provider and its credentials:

```bash
# OpenAI-compatible providers (ChatGPT, Kimi, Qwen, Mistral, DeepSeek, Custom, llama.cpp server)
LLM_PROVIDER=chatgpt
CHATGPT_API_KEY=sk-...
CHATGPT_BASE_URL=https://api.openai.com/v1
CHATGPT_MODEL=gpt-4o-mini

# Anthropic / Claude
LLM_PROVIDER=claude
CLAUDE_API_KEY=sk-ant-...
CLAUDE_BASE_URL=https://api.anthropic.com
CLAUDE_MODEL=claude-sonnet-4-20250514

# Google / Gemini
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIza...
GEMINI_BASE_URL=https://generativelanguage.googleapis.com/v1beta
GEMINI_MODEL=gemini-2.0-flash

# Ollama (native local API, no key required)
LLM_PROVIDER=ollama
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=llama2

# llama.cpp (OpenAI-compatible local server, no key required)
LLM_PROVIDER=llama-cpp
LLAMA_CPP_BASE_URL=http://localhost:8080/v1
LLAMA_CPP_MODEL=default
```

The UI provider selector can also use per-provider environment variables. For example, when the user selects ChatGPT, the backend first looks for `CHATGPT_API_KEY`, `CHATGPT_BASE_URL`, and `CHATGPT_MODEL`, then falls back to the `OPENAI_*` values. The same pattern works for `CLAUDE`/`ANTHROPIC`, `GEMINI`/`GOOGLE`, `KIMI`, `QWEN`, `MISTRAL`, `DEEPSEEK`, `CUSTOM`, `LLAMA_CPP`, and `OLLAMA`.

Then run:

```bash
set -a
source .env
set +a
uvicorn backend.app:app --reload --host 127.0.0.1 --port 8000
```

Only the sanitized prompt is sent to the provider. The app does not store the raw prompt, sanitized prompt, response, entity map, or risk report by default.

---

## API endpoints

### `POST /api/analyze`

Analyze and sanitize text.

Request:

```json
{
  "text": "My name is Ahmed and my phone is +971501234567",
  "stage": "input"
}
```

Response includes:

```json
{
  "original_risk_score": 85,
  "sanitized_risk_score": 10,
  "risk_level_before": "Critical",
  "risk_level_after": "Low",
  "detected_categories": ["PERSON_NAME", "CONTACT_PHONE"],
  "sanitized_text": "The user wants help with a privacy-sensitive request...",
  "send_to_llm": true
}
```

### `POST /api/chat`

Send a sanitized prompt to the LLM relay.

Request:

```json
{
  "provider": "chatgpt",
  "sanitized_prompt": "Write a polite email to a healthcare provider.",
  "client_report": {
    "original_risk_score": 90,
    "sanitized_risk_score": 15
  }
}
```

Response includes:

```json
{
  "safe_response": "...",
  "provider_mode": "mock",
  "provider": "chatgpt",
  "provider_label": "ChatGPT",
  "input_guard_report": {},
  "output_guard_report": {}
}
```

---

## Zero-retention implementation notes

The prototype is intentionally stateless:

- No database is used.
- No prompt or response body is logged.
- Browser-side analysis happens before the backend call.
- Backend performs a second guard pass only on the sanitized prompt.
- The entity map remains in browser memory only.
- The UI avoids `localStorage` and `sessionStorage`.
- Server logs should be configured to avoid request bodies in production.

---

## Test

Run:

```bash
python -m pytest backend/tests
```

---

## Important limitations

This is a research/prototype implementation. It is not a certified GDPR compliance product and is not legal advice. Production deployment should add legal review, DPIA support, vendor data-processing agreements, security testing, multilingual evaluation, accessibility testing, abuse handling, and stronger client-side ML/NER models.
