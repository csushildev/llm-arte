"""
Denial of Service (DoS) Protection
Monitors and limits resource consumption to prevent DoS attacks.
Covers: Rate limiting, token limits, request frequency.
"""
from datetime import datetime, timedelta
from collections import defaultdict

# ============================================================
# CONFIGURATION
# ============================================================
MAX_REQUESTS_PER_MINUTE = 10
MAX_REQUESTS_PER_HOUR = 100
MAX_TOKENS_PER_REQUEST = 5000
MAX_TOKENS_PER_HOUR = 50000
SUSPICIOUS_PATTERN_THRESHOLD = 5

# ============================================================
# TRACKING (In-memory - use Redis for production)
# ============================================================
request_history = defaultdict(list)
token_usage = defaultdict(int)
suspicious_requests = defaultdict(int)

# ============================================================
# TOKEN ESTIMATOR
# ============================================================
def estimate_tokens(text: str) -> int:
    """
    Rough estimation of tokens (4 chars ≈ 1 token).
    For production, use the actual tokenizer from the model.
    """
    return max(1, len(text) // 4)

# ============================================================
# DOS GUARDRAIL
# ============================================================
def check_dos_protection(
    user_id: str,
    prompt: str
) -> dict:
    """
    Check for DoS protection violations.
    Args:
        user_id: Identifier for the user/IP
        prompt: The prompt text
    Returns:
        Dictionary with allowed, category, message
    """
    now = datetime.now()
    minute_ago = now - timedelta(minutes=1)
    hour_ago = now - timedelta(hours=1)
    
    # --------------------------------------------------------
    # 1. Check tokens per request
    # --------------------------------------------------------
    prompt_tokens = estimate_tokens(prompt)
    if prompt_tokens > MAX_TOKENS_PER_REQUEST:
        return {
            "allowed": False,
            "category": "RATE_LIMIT_TOKENS",
            "message": (
                f"Prompt exceeds token limit. "
                f"Used: {prompt_tokens}, Max: {MAX_TOKENS_PER_REQUEST}"
            )
        }
    
    # --------------------------------------------------------
    # 2. Clean old requests
    # --------------------------------------------------------
    if user_id in request_history:
        request_history[user_id] = [
            ts for ts in request_history[user_id]
            if ts > minute_ago
        ]
    
    # --------------------------------------------------------
    # 3. Check requests per minute
    # --------------------------------------------------------
    requests_this_minute = len(request_history[user_id])
    if requests_this_minute >= MAX_REQUESTS_PER_MINUTE:
        return {
            "allowed": False,
            "category": "RATE_LIMIT_MINUTE",
            "message": (
                f"Too many requests. "
                f"Limit: {MAX_REQUESTS_PER_MINUTE}/min"
            )
        }
    
    # --------------------------------------------------------
    # 4. Check hourly token usage
    # --------------------------------------------------------
    hour_requests = [
        ts for ts in request_history[user_id]
        if ts > hour_ago
    ]
    current_hour_tokens = sum(
        estimate_tokens(prompt) 
        for _ in hour_requests
    )
    if (current_hour_tokens + prompt_tokens) > MAX_TOKENS_PER_HOUR:
        return {
            "allowed": False,
            "category": "RATE_LIMIT_HOUR",
            "message": (
                f"Hourly token limit exceeded. "
                f"Limit: {MAX_TOKENS_PER_HOUR}/hour"
            )
        }
    
    # --------------------------------------------------------
    # 5. Detect suspicious patterns
    # (repeated similar requests)
    # --------------------------------------------------------
    # Note: This is a simplified check. In production,
    # store actual prompts for comparison
    # For now, we just track frequency
    
    # --------------------------------------------------------
    # 6. Record the request
    # --------------------------------------------------------
    request_history[user_id].append(now)
    
    return {
        "allowed": True,
        "category": "SAFE",
        "message": "Request within rate limits."
    }


def reset_user_limits(user_id: str) -> None:
    """Reset rate limits for a user (admin function)."""
    if user_id in request_history:
        del request_history[user_id]
    if user_id in suspicious_requests:
        del suspicious_requests[user_id]
