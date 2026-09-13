import math
import re
import sqlite3
import uuid
from enum import Enum
from typing import List, Optional
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel

# --- 1. INITIALIZE DATABASE (SQLite - Completely Free & File-Based) ---
conn = sqlite3.connect("guardrail_gateway.db", check_same_thread=False)
cursor = conn.cursor()

# Create Tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS api_keys (
    key_id TEXT PRIMARY KEY,
    user_email TEXT NOT NULL,
    secret_key TEXT UNIQUE NOT NULL,
    request_count INTEGER DEFAULT 0,
    max_limit INTEGER DEFAULT 1000
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS audit_logs (
    log_id TEXT PRIMARY KEY,
    key_id TEXT,
    decision TEXT,
    risk_score REAL,
    threats TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

app = FastAPI(
    title="AI Guardrail Security Engine",
    description="Free, Self-Hosted Security Gateway for AI Models & Agents",
    version="1.0.0",
)

# --- 2. MODELS & SCHEMAS ---


class DecisionEnum(str, Enum):
    PASS = "PASS"
    SANITISED = "SANITISED"
    BLOCK = "BLOCK"


class UserRegisterRequest(BaseModel):
    email: str


class GuardrailRequest(BaseModel):
    user_prompt: str
    mask_pii: bool = True


class GuardrailResponse(BaseModel):
    decision: DecisionEnum
    processed_prompt: str
    risk_score: float
    detected_threats: List[str]


# --- 3. SECURITY SCANNING ENGINES ---

JAILBREAK_PATTERNS = [
    r"(?i)ignore\s+(all\s+)?previous\s+instructions",
    r"(?i)system\s+override",
    r"(?i)you\s+are\s+now\s+in\s+developer\s+mode",
    r"(?i)disregard\s+safety\s+rules",
    r"(?i)print\s+your\s+system\s+prompt",
    r"(?i)act\s+as\s+DAN",
]

PII_PATTERNS = {
    "API_KEY": r"(?i)(sk_live_[0-9a-zA-Z]{24}|ghp_[0-9a-zA-Z]{36}|api_key_[0-9a-zA-Z]{16,})",
    "EMAIL": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "CREDIT_CARD": r"\b(?:\d[ -]*?){13,16}\b",
    "PHONE": r"\b\d{10}\b",
}


def calculate_entropy(text: str) -> float:
    """Calculates text entropy to detect base64 or obfuscated payloads."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])


def scan_injection(text: str) -> tuple[bool, List[str]]:
    threats = []
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, text):
            threats.append(
                f"Prompt Injection / Jailbreak attempt matched: '{pattern}'"
            )

    # Entropy check for hidden payloads
    words = text.split()
    for word in words:
        if len(word) > 30 and calculate_entropy(word) > 4.5:
            threats.append(
                "Obfuscated / High-Entropy payload detected (Cipher/Base64)."
            )
            break

    return len(threats) > 0, threats


def sanitize_sensitive_data(text: str) -> tuple[str, List[str]]:
    threats = []
    cleaned_text = text
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, cleaned_text):
            threats.append(f"Sensitive Data Masked: {pii_type}")
            cleaned_text = re.sub(
                pattern, f"[REDACTED_{pii_type}]", cleaned_text
            )
    return cleaned_text, threats


# --- 4. AUTHENTICATION MIDDLEWARE ---


def verify_api_key(x_api_key: str = Header(...)) -> str:
    cursor.execute(
        "SELECT key_id, request_count, max_limit FROM api_keys WHERE secret_key = ?",
        (x_api_key,),
    )
    record = cursor.fetchone()

    if not record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key. Please register first.",
        )

    key_id, req_count, max_limit = record

    if req_count >= max_limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Free quota limit reached (1000 requests max).",
        )

    # Increment Usage Counter
    cursor.execute(
        "UPDATE api_keys SET request_count = request_count + 1 WHERE key_id = ?",
        (key_id,),
    )
    conn.commit()

    return key_id


# --- 5. API ENDPOINTS ---


@app.post("/v1/auth/register-free-key")
def register_user(user: UserRegisterRequest):
    """Generates a free API key for new developers."""
    key_id = str(uuid.uuid4())[:8]
    secret_key = f"gw_live_{str(uuid.uuid4()).replace('-', '')}"

    cursor.execute(
        "INSERT INTO api_keys (key_id, user_email, secret_key) VALUES (?, ?, ?)",
        (key_id, user.email, secret_key),
    )
    conn.commit()

    return {
        "status": "Success",
        "email": user.email,
        "api_key": secret_key,
        "free_quota": "1000 requests/month",
        "note": "Include 'x-api-key' header in your requests.",
    }


@app.post("/v1/guard/scan", response_model=GuardrailResponse)
def scan_prompt(
    request: GuardrailRequest, key_id: str = Depends(verify_api_key)
):
    """Scans and cleans prompts for LLM applications."""
    risk_score = 0.0
    detected_threats = []
    current_prompt = request.user_prompt

    # Step 1: Scan Injections
    is_injection, injection_threats = scan_injection(current_prompt)
    if is_injection:
        risk_score += 0.8
        detected_threats.extend(injection_threats)

    # Step 2: Scan & Mask PII
    cleaned_prompt, pii_threats = sanitize_sensitive_data(current_prompt)
    if pii_threats:
        risk_score += 0.3
        detected_threats.extend(pii_threats)
        if request.mask_pii:
            current_prompt = cleaned_prompt

    # Decision Logic
    final_risk = min(round(risk_score, 2), 1.0)

    if final_risk >= 0.8:
        decision = DecisionEnum.BLOCK
        current_prompt = ""
    elif final_risk >= 0.3:
        decision = DecisionEnum.SANITISED
    else:
        decision = DecisionEnum.PASS

    # Log Audit Record
    log_id = str(uuid.uuid4())[:8]
    cursor.execute(
        "INSERT INTO audit_logs (log_id, key_id, decision, risk_score, threats) VALUES (?, ?, ?, ?, ?)",
        (
            log_id,
            key_id,
            decision.value,
            final_risk,
            ", ".join(detected_threats),
        ),
    )
    conn.commit()

    return GuardrailResponse(
        decision=decision,
        processed_prompt=current_prompt,
        risk_score=final_risk,
        detected_threats=detected_threats,
    )