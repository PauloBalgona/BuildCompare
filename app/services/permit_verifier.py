from dataclasses import dataclass
from difflib import SequenceMatcher
import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from PIL import Image, UnidentifiedImageError
import io

DEFAULT_GEMINI_MODEL = "gemini-2.5-flash"


@dataclass
class PermitVerificationResult:
    auto_approve: bool
    file_hash: str
    method: str
    notes: str


def compute_file_sha256(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def _detect_actual_kind(file_bytes: bytes) -> str | None:
    if file_bytes.startswith(b"%PDF-"):
        return "pdf"
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if len(file_bytes) >= 12 and file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP":
        return "webp"
    return None


def _similarity(a: str, b: str) -> float:
    a_clean = re.sub(r"\s+", " ", (a or "").strip().lower())
    b_clean = re.sub(r"\s+", " ", (b or "").strip().lower())
    if not a_clean or not b_clean:
        return 0.0
    return SequenceMatcher(None, a_clean, b_clean).ratio()


def _inspect_pdf_metadata(file_bytes: bytes) -> list[str]:
    flags: list[str] = []
    lower_sample = file_bytes[:65536].decode("latin-1", errors="ignore").lower()
    suspicious_generators = [
        "canva",
        "midjourney",
        "dall-e",
        "dalle",
        "firefly",
        "photoshop",
        "figma",
        "illustrator",
    ]
    for marker in suspicious_generators:
        if marker in lower_sample:
            flags.append(f"PDF metadata mentions '{marker}' (requires manual check)")
            break
    return flags


def _inspect_image_properties(file_bytes: bytes) -> tuple[list[str], str]:
    flags: list[str] = []
    try:
        with Image.open(io.BytesIO(file_bytes)) as img:
            width, height = img.size
            mime_type = Image.MIME.get(img.format or "", "image/jpeg")
            if min(width, height) < 500:
                flags.append(f"Low image resolution ({width}x{height}px)")
            return flags, mime_type
    except UnidentifiedImageError:
        return ["Unreadable or corrupted image file"], "application/octet-stream"


def _call_gemini_permit_check(
    file_bytes: bytes,
    mime_type: str,
    store_name: str,
    store_location: str,
) -> dict | None:
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        return None

    model = os.environ.get("GEMINI_PERMIT_MODEL", DEFAULT_GEMINI_MODEL).strip() or DEFAULT_GEMINI_MODEL
    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"

    import base64

    encoded_data = base64.b64encode(file_bytes).decode("ascii")

    prompt = (
        "You are a document verification assistant for a hardware & construction supply platform.\n"
        "Inspect the uploaded business permit / registration document carefully.\n"
        f"Applicant claimed store name: {store_name}\n"
        f"Applicant claimed store location: {store_location}\n\n"
        "Check for:\n"
        "1. Whether the document looks like a genuine business permit, DTI/SEC registration, or Mayor's permit.\n"
        "2. Whether there are signs of AI generation, digital tampering, inconsistent fonts/alignment, or blurred/unreadable text.\n"
        "3. Extracted business name, extracted location/city/address, and whether a current/recent valid year (e.g. 2025 or 2026) is shown.\n\n"
        "Respond ONLY with valid JSON matching this schema:\n"
        "{\n"
        '  "is_permit_document": true/false,\n'
        '  "extracted_business_name": "string",\n'
        '  "extracted_location": "string",\n'
        '  "has_valid_recent_year": true/false,\n'
        '  "ai_or_tamper_suspicion": true/false,\n'
        '  "confidence_score": 0.0 to 1.0,\n'
        '  "summary_reason": "short reason"\n'
        "}"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                    {
                        "inline_data": {
                            "mime_type": mime_type,
                            "data": encoded_data,
                        }
                    },
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "responseMimeType": "application/json",
        },
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=25) as resp:
            raw_body = resp.read().decode("utf-8", errors="ignore")
            parsed = json.loads(raw_body)
            candidates = parsed.get("candidates") or []
            if not candidates:
                return None
            parts = ((candidates[0].get("content") or {}).get("parts")) or []
            text_out = "".join(p.get("text", "") for p in parts if isinstance(p, dict)).strip()
            if not text_out:
                return None
            return json.loads(text_out)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        return None


def verify_business_permit(
    file_bytes: bytes,
    store_name: str,
    store_location: str,
    duplicate_exists: bool = False,
) -> PermitVerificationResult:
    file_hash = compute_file_sha256(file_bytes)
    reasons_for_review: list[str] = []

    if duplicate_exists:
        reasons_for_review.append("Duplicate permit file detected across accounts")

    actual_kind = _detect_actual_kind(file_bytes)
    if not actual_kind:
        reasons_for_review.append("Unrecognized file header/signature")
        return PermitVerificationResult(
            auto_approve=False,
            file_hash=file_hash,
            method="rule_check",
            notes="Flagged for admin review: " + "; ".join(reasons_for_review),
        )

    if actual_kind == "pdf":
        reasons_for_review.extend(_inspect_pdf_metadata(file_bytes))
        mime_type = "application/pdf"
    else:
        img_flags, mime_type = _inspect_image_properties(file_bytes)
        reasons_for_review.extend(img_flags)

    ai_result = _call_gemini_permit_check(
        file_bytes=file_bytes,
        mime_type=mime_type,
        store_name=store_name,
        store_location=store_location,
    )

    if not ai_result:
        reasons_for_review.append("Automated AI check unavailable or timed out")
        return PermitVerificationResult(
            auto_approve=False,
            file_hash=file_hash,
            method="rule_check",
            notes="Flagged for admin review: " + "; ".join(reasons_for_review),
        )

    is_permit = bool(ai_result.get("is_permit_document"))
    tamper_suspected = bool(ai_result.get("ai_or_tamper_suspicion"))
    valid_year = bool(ai_result.get("has_valid_recent_year"))
    confidence = float(ai_result.get("confidence_score") or 0.0)
    extracted_name = str(ai_result.get("extracted_business_name") or "")
    extracted_loc = str(ai_result.get("extracted_location") or "")
    ai_reason = str(ai_result.get("summary_reason") or "").strip()

    name_sim = _similarity(store_name, extracted_name)
    loc_sim = _similarity(store_location, extracted_loc)

    if not is_permit:
        reasons_for_review.append("Document does not clearly appear to be a valid business permit")
    if tamper_suspected:
        reasons_for_review.append("Potential AI generation or document tampering detected")
    if not valid_year:
        reasons_for_review.append("Permit year/validity could not be confirmed as current")
    if confidence < 0.75:
        reasons_for_review.append(f"Low verification confidence ({confidence:.2f})")
    if name_sim < 0.65:
        reasons_for_review.append(
            f"Store name mismatch (form: '{store_name}' vs permit: '{extracted_name}')"
        )
    if loc_sim < 0.50:
        reasons_for_review.append(
            f"Location mismatch (form: '{store_location}' vs permit: '{extracted_loc}')"
        )

    if not reasons_for_review:
        notes = (
            f"Auto-approved via AI (conf={confidence:.2f}, name_sim={name_sim:.2f}, loc_sim={loc_sim:.2f}). "
            f"{ai_reason}".strip()
        )
        return PermitVerificationResult(
            auto_approve=True,
            file_hash=file_hash,
            method="auto_ai",
            notes=notes,
        )

    notes = "Flagged for admin review: " + "; ".join(reasons_for_review)
    if ai_reason:
        notes += f" | AI note: {ai_reason}"

    return PermitVerificationResult(
        auto_approve=False,
        file_hash=file_hash,
        method="auto_ai",
        notes=notes,
    )