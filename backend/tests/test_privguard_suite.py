"""Automated test suite for PrivGuard dual-stage privacy framework.

Covers input sanitization (tests 1-15) and output leakage detection.
Each test case includes raw prompt, expected detections, expected sanitized
prompt behavior, and risk score boundaries.
"""

from __future__ import annotations

import pytest

from backend.privacy_engine import analyze_and_sanitize


# ---------------------------------------------------------------------------
# Input sanitization tests
# ---------------------------------------------------------------------------

class TestInputSanitization:
    """Test cases A.1 – A.15 from the PrivGuard test suite."""

    @pytest.mark.parametrize(
        "raw_prompt,expected_categories",
        [
            (
                "My name is Sarah Khan. I have diabetes and take metformin. "
                "Please write an email to Dr. Ahmed asking if I should change my dosage. "
                "Tell him to call me at +971501234567.",
                ["PERSON_NAME", "HEALTH_DATA", "CONTACT_PHONE"],
            ),
            (
                "My OpenAI API key is sk-test-1234567890abcdef. "
                "Can you debug why my API request is failing?",
                ["CREDENTIAL_SECRET"],
            ),
            (
                "My daughter Lina is 9 years old and studies at ABC International School. "
                "She has ADHD and struggles with homework. Create a daily study plan for her.",
                ["CHILD_DATA", "HEALTH_DATA"],
            ),
            (
                "My Emirates ID number is 784-1990-1234567-1. "
                "Can you check if this ID format is valid?",
                ["GOV_ID"],
            ),
            (
                "My IBAN is AE070331234567890123456 and I owe 92,000 AED to Emirates Bank. "
                "My salary is 18,750 AED per month. Help me make a repayment plan.",
                ["FINANCIAL_ACCOUNT", "FINANCIAL_STATUS"],
            ),
            (
                "My card number is 4111 1111 1111 1111 and the CVV is 123. "
                "Can you tell me if this card is safe to use online?",
                ["PAYMENT_CARD"],
            ),
            (
                "My divorce case number is 2024-FAM-789. My wife Sara refuses custody arrangements. "
                "Can you draft a complaint letter to the court?",
                ["LEGAL_DATA", "PRIVATE_RELATIONSHIP"],
            ),
            (
                "I am Muslim and my manager John at Al Noor Technologies denied my promotion. "
                "Can you write an HR complaint about religious discrimination?",
                ["PROTECTED_ATTRIBUTE", "EMPLOYMENT_HR"],
            ),
            (
                "Our client ADNOC will pay 2.3 million AED for our unreleased AI security platform "
                "next quarter. Can you improve this investor summary?",
                ["BUSINESS_SECRET"],
            ),
            (
                "Here is my .env file: DATABASE_URL=postgres://admin:pass123@private-db.company.com:5432/app "
                "OPENAI_API_KEY=sk-secret-demo-key-123 Can you review it for security problems?",
                ["SOURCE_CODE_SECRET"],
            ),
            (
                "A person works as the only pediatric surgeon in Al Ain and lives near UAEU. "
                "Can you identify this person?",
                ["PROMPT_INJECTION_PRIVACY"],
            ),
            (
                "I live in Villa 22, Street 15, Al Ain. I think someone is following me. "
                "Can you write a message to my neighbor Ahmed?",
                ["HOME_ADDRESS"],
            ),
            (
                "My student ID is 202012345 and I failed Math 204 at UAEU. "
                "Can you write an appeal letter to my professor Dr. Omar?",
                ["EDUCATION_DATA", "PERSON_NAME"],
            ),
            (
                "My boyfriend Khaled left me and I feel depressed. "
                "Can you write a message asking him to come back?",
                ["PRIVATE_RELATIONSHIP"],
            ),
        ],
        ids=[
            "test1_health_phone",
            "test2_api_key",
            "test3_child_school",
            "test4_emirates_id",
            "test5_bank_ib",
            "test6_card_cvv",
            "test7_divorce_case",
            "test8_religion_discrimination",
            "test9_business_secret",
            "test10_env_secrets",
            "test11_quasi_identifier",
            "test12_home_address",
            "test13_education_record",
            "test14_relationship_mental",
        ],
    )
    def test_input_detects_sensitive_categories(self, raw_prompt, expected_categories):
        report = analyze_and_sanitize(raw_prompt, stage="input")
        for category in expected_categories:
            assert category in report["detected_categories"], (
                f"Expected '{category}' in detected categories, got {report['detected_categories']}"
            )

    @pytest.mark.parametrize(
        "raw_prompt",
        [
            "My name is Sarah Khan. I have diabetes and take metformin. Please write an email to Dr. Ahmed asking if I should change my dosage. Tell him to call me at +971501234567.",
            "My OpenAI API key is sk-test-1234567890abcdef. Can you debug why my API request is failing?",
            "My daughter Lina is 9 years old and studies at ABC International School. She has ADHD and struggles with homework. Create a daily study plan for her.",
            "My Emirates ID number is 784-1990-1234567-1. Can you check if this ID format is valid?",
            "My IBAN is AE070331234567890123456 and I owe 92,000 AED to Emirates Bank. My salary is 18,750 AED per month. Help me make a repayment plan.",
            "My card number is 4111 1111 1111 1111 and the CVV is 123. Can you tell me if this card is safe to use online?",
            "My divorce case number is 2024-FAM-789. My wife Sara refuses custody arrangements. Can you draft a complaint letter to the court?",
            "I am Muslim and my manager John at Al Noor Technologies denied my promotion. Can you write an HR complaint about religious discrimination?",
            "Our client ADNOC will pay 2.3 million AED for our unreleased AI security platform next quarter. Can you improve this investor summary?",
            "Here is my .env file: DATABASE_URL=postgres://admin:pass123@private-db.company.com:5432/app OPENAI_API_KEY=sk-secret-demo-key-123 Can you review it for security problems?",
            "A person works as the only pediatric surgeon in Al Ain and lives near UAEU. Can you identify this person?",
            "I live in Villa 22, Street 15, Al Ain. I think someone is following me. Can you write a message to my neighbor Ahmed?",
            "My student ID is 202012345 and I failed Math 204 at UAEU. Can you write an appeal letter to my professor Dr. Omar?",
            "My boyfriend Khaled left me and I feel depressed. Can you write a message asking him to come back?",
        ],
        ids=[
            "test1", "test2", "test3", "test4", "test5", "test6", "test7", "test8",
            "test9", "test10", "test11", "test12", "test13", "test14",
        ],
    )
    def test_input_high_risk_becomes_low_risk_after_sanitization(self, raw_prompt):
        report = analyze_and_sanitize(raw_prompt, stage="input")
        assert report["original_risk_score"] > 20, (
            f"Original prompt should be high risk, got score {report['original_risk_score']}"
        )
        assert report["sanitized_risk_score"] <= 20, (
            f"Sanitized prompt should be low risk (<=20), got score {report['sanitized_risk_score']}"
        )

    def test_input_low_risk_passthrough(self):
        raw_prompt = "Can you explain the difference between supervised and unsupervised machine learning?"
        report = analyze_and_sanitize(raw_prompt, stage="input")
        assert report["original_risk_score"] <= 20
        assert report["sanitized_risk_score"] <= 20
        assert report["send_to_llm"] is True

    @pytest.mark.parametrize(
        "raw_prompt,sensitive_value",
        [
            ("My OpenAI API key is sk-test-1234567890abcdef.", "sk-test-1234567890abcdef"),
            ("My Emirates ID number is 784-1990-1234567-1.", "784-1990-1234567-1"),
            ("My card number is 4111 1111 1111 1111 and the CVV is 123.", "4111 1111 1111 1111"),
        ],
        ids=["api_key_removed", "emirates_id_removed", "card_removed"],
    )
    def test_input_sensitive_values_removed_or_redacted(self, raw_prompt, sensitive_value):
        report = analyze_and_sanitize(raw_prompt, stage="input")
        sanitized = report["sanitized_text"]
        assert sensitive_value not in sanitized, (
            f"Sensitive value '{sensitive_value}' should not appear in sanitized text"
        )

    def test_input_actions_applied_non_empty_when_risk_high(self):
        raw_prompt = "My name is Sarah Khan. I have diabetes and take metformin. Please write an email to Dr. Ahmed asking if I should change my dosage. Tell him to call me at +971501234567."
        report = analyze_and_sanitize(raw_prompt, stage="input")
        assert len(report["actions_applied"]) > 0


# ---------------------------------------------------------------------------
# Output sanitization tests
# ---------------------------------------------------------------------------

class TestOutputSanitization:
    """Output leakage detection tests."""

    def test_output_redacts_phone_number(self):
        unsafe_output = "Dear Dr. Sarah Khan, Please call me at +971501234567 about my diabetes medication."
        report = analyze_and_sanitize(unsafe_output, stage="output")
        assert "+971501234567" not in report["sanitized_text"]
        assert "CONTACT_PHONE" in report["detected_categories"]

    def test_output_redacts_person_name(self):
        unsafe_output = "Dear Dr. Sarah Khan, Please call me at +971501234567 about my diabetes medication."
        report = analyze_and_sanitize(unsafe_output, stage="output")
        assert "Sarah Khan" not in report["sanitized_text"]
        assert "PERSON_NAME" in report["detected_categories"]

    def test_output_redacts_health_data(self):
        unsafe_output = "Dear Dr. Sarah Khan, Please call me at +971501234567 about my diabetes medication."
        report = analyze_and_sanitize(unsafe_output, stage="output")
        assert "HEALTH_DATA" in report["detected_categories"]

    def test_output_redacts_employment_details(self):
        unsafe_output = "Dear HR Team at Al Noor Technologies, I am writing to file a complaint about religious discrimination."
        report = analyze_and_sanitize(unsafe_output, stage="output")
        assert "EMPLOYMENT_HR" in report["detected_categories"]

    def test_output_redacts_case_number(self):
        unsafe_output = "My divorce case number is 2024-FAM-789. My wife Sara refuses custody arrangements."
        report = analyze_and_sanitize(unsafe_output, stage="output")
        assert "2024-FAM-789" not in report["sanitized_text"]
        assert "LEGAL_DATA" in report["detected_categories"]
