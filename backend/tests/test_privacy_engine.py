from backend.privacy_engine import analyze_and_sanitize, detect_sensitive_data


def test_detects_phone_and_health_data():
    text = "My name is Ahmed. I have diabetes and my phone is +971501234567."
    detections = detect_sensitive_data(text)
    categories = {d.type for d in detections}
    assert "HEALTH_DATA" in categories
    assert "CONTACT_PHONE" in categories


def test_critical_secret_is_removed_from_sanitized_prompt():
    text = "Debug this. OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456"
    report = analyze_and_sanitize(text, stage="input")
    assert report["original_risk_score"] == 100
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in report["sanitized_text"]
    assert report["send_to_llm"] is True


def test_payment_card_is_blocked():
    text = "My card is 4111 1111 1111 1111 and CVV 123. Can you check it?"
    report = analyze_and_sanitize(text, stage="input")
    assert "PAYMENT_CARD" in report["detected_categories"]
    assert "4111" not in report["sanitized_text"]
    assert report["original_risk_score"] == 100


def test_output_redacts_email():
    text = "Contact the user at person@example.com for details."
    report = analyze_and_sanitize(text, stage="output")
    assert "person@example.com" not in report["sanitized_text"]
    assert "[EMAIL]" in report["sanitized_text"]


def test_low_risk_prompt_can_pass():
    text = "Explain what data minimization means in simple terms."
    report = analyze_and_sanitize(text, stage="input")
    assert report["sanitized_risk_score"] <= 20
    assert report["send_to_llm"] is True
