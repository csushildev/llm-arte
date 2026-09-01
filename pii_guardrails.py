"""
PII (Personally Identifiable Information) Detection Guardrail
Detects sensitive personal data patterns in both input and output.
Covers: SSN, credit cards, email, phone, passport, etc.
"""
import re

# ============================================================
# PII PATTERNS
# ============================================================
PII_PATTERNS = {
    "ssn": r"\b\d{3}-\d{2}-\d{4}\b",  # 123-45-6789
    "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",  # 1234-5678-9012-3456
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone_us": r"\b(\+?1)?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b",
    "passport": r"\b[A-Z]{1,2}\d{6,9}\b",  # US/UK passport format
    "ip_address": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
    "credit_card_word": r"\b(?:credit\s+card|card\s+number|cvv|cvc)\b",
    "bank_account": r"\b(?:account\s+number|routing\s+number)\b",
    "medical_info": r"\b(?:social\s+security|medicare|medicaid)\b",
}

# ============================================================
# PII GUARDRAIL
# ============================================================
def check_pii(text: str, context: str = "output") -> dict:
    """
    Check for PII in text.
    Args:
        text: The text to check
        context: "input" or "output" (for different severity)
    Returns:
        Dictionary with allowed, category, message, and detected_pii
    """
    if not text or not isinstance(text, str):
        return {
            "allowed": True,
            "category": "SAFE",
            "message": "No text to check.",
            "detected_pii": []
        }
    
    detected = []
    text_lower = text.lower()
    
    # Check each pattern
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.finditer(pattern, text)
        for match in matches:
            detected.append({
                "type": pii_type,
                "value": match.group(0),
                "position": match.start()
            })
    
    # Determine severity based on context
    if detected:
        severity = "critical" if context == "output" else "high"
        return {
            "allowed": False,
            "category": "PII_DETECTED",
            "message": (
                f"Personally Identifiable Information detected: "
                f"{', '.join([d['type'] for d in detected])}"
            ),
            "detected_pii": detected,
            "severity": severity
        }
    
    return {
        "allowed": True,
        "category": "SAFE",
        "message": "No PII patterns detected.",
        "detected_pii": []
    }
