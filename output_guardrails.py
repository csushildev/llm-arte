"""
Output Guardrails

Checks Gemini's response before returning it to the user.
Enhanced with XSS, code injection, and unsafe format detection.
"""
import re

# ============================================================
# BLOCKED OUTPUT PATTERNS (Enhanced)
# ============================================================
BLOCKED_OUTPUT_PATTERNS = [
    "api key",
    "api_key",
    "secret key",
    "password",
    "private key",
    "access token",
    "bearer token",
    "authorization header",
]

# ============================================================
# XSS PATTERNS
# ============================================================
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"on\w+\s*=",  # onclick=, onload=, etc.
    r"javascript:",
    r"<iframe",
    r"<object",
    r"<embed",
]

# ============================================================
# CODE INJECTION PATTERNS
# ============================================================
CODE_INJECTION_PATTERNS = [
    r"<\?php",
    r"<%.*%>",
    r"eval\s*\(",
    r"exec\s*\(",
    r"system\s*\(",
    r"import\s+os",
    r"__import__",
]

# ============================================================
# UNSAFE FORMAT PATTERNS
# ============================================================
UNSAFE_FORMAT_PATTERNS = [
    r"<!DOCTYPE",
    r"<html",
    r"<body",
]
# ============================================================
# OUTPUT GUARDRAIL
# ============================================================
def check_output(output: str) -> dict:
    """
    Validate Gemini output.
    Enhanced checks for sensitive info, XSS, code injection.
    Returns:
    allowed
    category
    message
    """
    # --------------------------------------------------------
    # 1. Empty output
    # --------------------------------------------------------
    if not output or not output.strip():
        return {
            "allowed": False,
            "category": "EMPTY_OUTPUT",
            "message": (
                "Model returned an empty response."
            )
        }
    # --------------------------------------------------------
    # 2. Normalize
    # --------------------------------------------------------
    text = output.lower()
    
    # --------------------------------------------------------
    # 3. Sensitive information
    # --------------------------------------------------------
    for pattern in BLOCKED_OUTPUT_PATTERNS:
        if pattern in text:
            return {
                "allowed": False,
                "category": "SENSITIVE_OUTPUT",
                "message": (
                    "Potentially sensitive information "
                    "detected in model output."
                )
            }
    
    # --------------------------------------------------------
    # 4. XSS Detection
    # --------------------------------------------------------
    for xss_pattern in XSS_PATTERNS:
        if re.search(xss_pattern, output, re.IGNORECASE | re.DOTALL):
            return {
                "allowed": False,
                "category": "XSS_DETECTED",
                "message": (
                    "Potentially malicious HTML/JavaScript detected."
                )
            }
    
    # --------------------------------------------------------
    # 5. Code Injection Detection
    # --------------------------------------------------------
    for code_pattern in CODE_INJECTION_PATTERNS:
        if re.search(code_pattern, output, re.IGNORECASE):
            return {
                "allowed": False,
                "category": "CODE_INJECTION_DETECTED",
                "message": (
                    "Potentially malicious code detected in output."
                )
            }
    
    # --------------------------------------------------------
    # 6. Unsafe Format Detection
    # --------------------------------------------------------
    for unsafe_pattern in UNSAFE_FORMAT_PATTERNS:
        if re.search(unsafe_pattern, output, re.IGNORECASE):
            return {
                "allowed": False,
                "category": "UNSAFE_FORMAT",
                "message": (
                    "Unsafe document format detected."
                )
            }
    
    # --------------------------------------------------------
    # 7. Safe output
    # --------------------------------------------------------
    return {
        "allowed": True,
        "category": "SAFE",
        "message": "Output passed the guardrail."
    }