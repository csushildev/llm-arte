"""
Plugin Validation Guardrail
Validates function calls and plugin usage to prevent malicious plugin injection.
Covers: Function call validation, parameter sanitization, allowlist.
"""
import json
import re

# ============================================================
# ALLOWED PLUGINS/FUNCTIONS
# ============================================================
ALLOWED_FUNCTIONS = {
    "search": {
        "description": "Search the internet",
        "parameters": ["query", "max_results"],
        "max_query_length": 200
    },
    "calculate": {
        "description": "Perform mathematical calculations",
        "parameters": ["expression"],
        "max_length": 100
    },
    "get_current_time": {
        "description": "Get current date/time",
        "parameters": [],
        "max_length": 0
    },
    "get_weather": {
        "description": "Get weather information",
        "parameters": ["location"],
        "max_length": 100
    }
}

# ============================================================
# BLOCKED FUNCTION NAMES
# ============================================================
BLOCKED_FUNCTIONS = [
    "exec",
    "eval",
    "system",
    "os.system",
    "subprocess",
    "__import__",
    "compile",
]

# ============================================================
# DANGEROUS PARAMETER PATTERNS
# ============================================================
DANGEROUS_PATTERNS = [
    r"import\s+",
    r"__.*__",
    r"subprocess",
    r"os\.system",
    r"eval\s*\(",
    r"exec\s*\(",
    r"open\s*\(",
    r"input\s*\(",
    r"\$\{.*\}",  # Template injection
    r"`.*`",      # Command injection
]

# ============================================================
# VALIDATE FUNCTION CALL
# ============================================================
def validate_function_call(
    function_name: str,
    parameters: dict
) -> dict:
    """
    Validate a function call request.
    Args:
        function_name: Name of the function to call
        parameters: Dictionary of parameters
    Returns:
        Dictionary with allowed, category, message
    """
    # --------------------------------------------------------
    # 1. Check if function is blocked
    # --------------------------------------------------------
    if function_name in BLOCKED_FUNCTIONS:
        return {
            "allowed": False,
            "category": "BLOCKED_FUNCTION",
            "message": f"Function '{function_name}' is not allowed."
        }
    
    # --------------------------------------------------------
    # 2. Check if function is in allowlist
    # --------------------------------------------------------
    if function_name not in ALLOWED_FUNCTIONS:
        return {
            "allowed": False,
            "category": "UNKNOWN_FUNCTION",
            "message": (
                f"Function '{function_name}' is not in the "
                f"allowed plugins list."
            )
        }
    
    func_spec = ALLOWED_FUNCTIONS[function_name]
    
    # --------------------------------------------------------
    # 3. Validate parameters
    # --------------------------------------------------------
    if not isinstance(parameters, dict):
        return {
            "allowed": False,
            "category": "INVALID_PARAMETERS",
            "message": "Parameters must be a dictionary."
        }
    
    # --------------------------------------------------------
    # 4. Check for unexpected parameters
    # --------------------------------------------------------
    expected_params = set(func_spec["parameters"])
    provided_params = set(parameters.keys())
    
    unexpected = provided_params - expected_params
    if unexpected and function_name != "search":  # search can have extra params
        return {
            "allowed": False,
            "category": "UNEXPECTED_PARAMETERS",
            "message": (
                f"Unexpected parameters: {', '.join(unexpected)}"
            )
        }
    
    missing = expected_params - provided_params
    if missing:
        return {
            "allowed": False,
            "category": "MISSING_PARAMETERS",
            "message": (
                f"Missing required parameters: {', '.join(missing)}"
            )
        }
    
    # --------------------------------------------------------
    # 5. Validate parameter values
    # --------------------------------------------------------
    for param_name, param_value in parameters.items():
        if not isinstance(param_value, str):
            param_value = str(param_value)
        
        # Check max length - look for param-specific limit first, then general limit
        max_len = func_spec.get(f"max_{param_name}_length", 
                                func_spec.get("max_length", 500))
        if len(param_value) > max_len:
            return {
                "allowed": False,
                "category": "PARAMETER_TOO_LONG",
                "message": (
                    f"Parameter '{param_name}' exceeds max length "
                    f"({len(param_value)} > {max_len})"
                )
            }
        
        # Check for dangerous patterns
        for dangerous_pattern in DANGEROUS_PATTERNS:
            if re.search(dangerous_pattern, param_value, re.IGNORECASE):
                return {
                    "allowed": False,
                    "category": "DANGEROUS_PARAMETER",
                    "message": (
                        f"Parameter '{param_name}' contains "
                        f"potentially dangerous code."
                    )
                }
    
    # --------------------------------------------------------
    # 6. Valid function call
    # --------------------------------------------------------
    return {
        "allowed": True,
        "category": "VALID_FUNCTION_CALL",
        "message": (
            f"Function '{function_name}' is valid and allowed."
        ),
        "function": function_name,
        "parameters": parameters
    }

# ============================================================
# VALIDATE PLUGIN RESPONSE
# ============================================================
def validate_plugin_response(
    function_name: str,
    response: str
) -> dict:
    """
    Validate the response from a plugin before returning to user.
    """
    if not response or not isinstance(response, str):
        return {
            "allowed": False,
            "category": "INVALID_RESPONSE",
            "message": "Plugin response is invalid."
        }
    
    # Check for sensitive information in response
    dangerous_keywords = [
        "api_key",
        "api key",
        "password",
        "secret",
        "token",
        "sk_live",  # Stripe key pattern
        "sk_test",  # Stripe key pattern
    ]
    
    response_lower = response.lower()
    for keyword in dangerous_keywords:
        if keyword in response_lower:
            return {
                "allowed": False,
                "category": "SENSITIVE_PLUGIN_RESPONSE",
                "message": (
                    f"Plugin response contains potentially sensitive data."
                )
            }
    
    return {
        "allowed": True,
        "category": "VALID_RESPONSE",
        "message": "Plugin response is valid."
    }
