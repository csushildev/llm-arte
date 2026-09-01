"""
FastAPI Application
LLM Guardrails - Enhanced OWASP Top 10 Protection
"""
from fastapi import FastAPI, Request, Header
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from guardrails import check_input
from output_guardrails import check_output
from pii_guardrails import check_pii
from dos_protection import check_dos_protection
from auth_guardrails import check_auth_guardrail
from plugin_validation import validate_function_call
from gemini_service import generate_response
# ============================================================
# FastAPI Application
# ============================================================
app = FastAPI(
    title="LLM Guardrails POC - Enhanced",
    description=(
        "Gemini + FastAPI + "
        "OWASP Top 10 Input and Output Guardrails"
    ),
    version="2.0.0",
)
# ============================================================
# Static Files
# ============================================================

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static",
)
# ============================================================
# Templates
# ============================================================
templates = Jinja2Templates(
    directory="templates"
)
# ============================================================
# Request Models
# ============================================================
class PromptRequest(BaseModel):
    prompt: str
    api_key: str = "demo_key_001"  # Default for testing


class FunctionCallRequest(BaseModel):
    function_name: str
    parameters: dict
    api_key: str = "demo_key_001"


# ============================================================
# Home Page
# ============================================================
@app.get(
    "/",
    response_class=HTMLResponse
)
async def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={}
    )
# ============================================================
# Health Check
# ============================================================
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "application": "LLM Guardrails Workshop - Enhanced",
        "version": "2.0.0"
    }
# ============================================================
# Generate (Enhanced with all guardrails)
# ============================================================
@app.post("/generate")
async def generate(
    request: PromptRequest,
    x_user_id: str = Header("anonymous")
):
    user_input = request.prompt
    api_key = request.api_key
    
    # ========================================================
    # STEP 0: AUTHENTICATION
    # ========================================================
    auth_result = check_auth_guardrail(api_key)
    if not auth_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "auth_guardrail",
            "category": auth_result["category"],
            "message": auth_result["message"],
            "response": None
        }
    
    # ========================================================
    # STEP 1: DOS PROTECTION
    # ========================================================
    dos_result = check_dos_protection(x_user_id, user_input)
    if not dos_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "dos_protection",
            "category": dos_result["category"],
            "message": dos_result["message"],
            "response": None
        }
    
    # ========================================================
    # STEP 2: PII CHECK (Input)
    # ========================================================
    pii_input_result = check_pii(user_input, context="input")
    if not pii_input_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "input_pii_guardrail",
            "category": pii_input_result["category"],
            "message": pii_input_result["message"],
            "response": None,
            "details": pii_input_result.get("detected_pii", [])
        }
    
    # ========================================================
    # STEP 3: INPUT GUARDRAIL (Enhanced)
    # ========================================================
    input_result = check_input(user_input)
    if not input_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "input_guardrail",
            "category": input_result["category"],
            "message": input_result["message"],
            "response": None
        }
    
    # ========================================================
    # STEP 4: GEMINI
    # ========================================================
    model_response = generate_response(user_input)
    
    # ========================================================
    # STEP 5: PII CHECK (Output)
    # ========================================================
    pii_output_result = check_pii(
        model_response,
        context="output"
    )
    if not pii_output_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "output_pii_guardrail",
            "category": pii_output_result["category"],
            "message": pii_output_result["message"],
            "response": None,
            "details": pii_output_result.get("detected_pii", [])
        }
    
    # ========================================================
    # STEP 6: OUTPUT GUARDRAIL (Enhanced)
    # ========================================================
    output_result = check_output(model_response)
    if not output_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "output_guardrail",
            "category": output_result["category"],
            "message": output_result["message"],
            "response": None
        }
    
    # ========================================================
    # STEP 7: SUCCESS
    # ========================================================
    return {
        "status": "success",
        "stage": "completed",
        "category": "SAFE",
        "message": "Response generated successfully.",
        "response": model_response,
        "user": auth_result.get("user")
    }


# ========================================================
# FUNCTION CALL VALIDATION ENDPOINT
# ========================================================
@app.post("/validate-function-call")
async def validate_function(
    request: FunctionCallRequest,
    x_user_id: str = Header("anonymous")
):
    """
    Endpoint to validate plugin/function calls.
    """
    # Auth check
    auth_result = check_auth_guardrail(request.api_key)
    if not auth_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "auth_guardrail",
            "category": auth_result["category"],
            "message": auth_result["message"]
        }
    
    # Validate function call
    validation_result = validate_function_call(
        request.function_name,
        request.parameters
    )
    
    if not validation_result["allowed"]:
        return {
            "status": "blocked",
            "stage": "plugin_validation",
            "category": validation_result["category"],
            "message": validation_result["message"]
        }
    
    return {
        "status": "valid",
        "stage": "plugin_validation",
        "category": "VALID_FUNCTION_CALL",
        "message": validation_result["message"],
        "function": validation_result.get("function"),
        "parameters": validation_result.get("parameters")
    }
