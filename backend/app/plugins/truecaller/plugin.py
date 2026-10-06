"""
SPAIDER Truecaller Plugin — Phone number intelligence and identity lookup.
Uses the unofficial Truecaller API / truecallerpy library.
Requires TRUECALLER_AUTH_TOKEN in environment / .env
"""

import os
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = (
    "⚠️ Phone number lookups may constitute personal data processing under GDPR/privacy laws. "
    "Only query numbers you are legally authorised to investigate."
)

PLUGIN_META = {
    "name": "truecaller",
    "version": "1.0",
    "category": "OSINT",
    "description": "Phone number intelligence — caller identity, spam score, carrier, location, and social profile enrichment.",
}


def lookup(phone: str, country_code: str = "IN", auth_token: Optional[str] = None) -> dict:
    """
    Lookup a phone number via Truecaller.
    phone: phone number without country code prefix (e.g. '9876543210')
    country_code: ISO 2-letter country code (default 'IN')
    auth_token: Truecaller auth token (from truecallerpy login)
    """
    token = auth_token or os.getenv("TRUECALLER_AUTH_TOKEN", "")
    if not token:
        logger.warning("No Truecaller auth token — returning mock data")
        return _mock_result(phone, country_code)

    try:
        from truecallerpy import search_phonenumber  # pip install truecallerpy
        import asyncio

        result = asyncio.run(search_phonenumber(phone, country_code, token))
        return _parse_result(result, phone)

    except ImportError:
        logger.warning("truecallerpy not installed — pip install truecallerpy")
        return _mock_result(phone, country_code)
    except Exception as e:
        logger.error("Truecaller API error", error=str(e))
        return {"error": str(e), "phone": phone, "authorization_warning": AUTH_WARNING}


def _parse_result(data: dict, phone: str) -> dict:
    """Parse Truecaller API response into SPAIDER schema."""
    if not data or data.get("status") != 200:
        return {
            "phone": phone,
            "found": False,
            "error": data.get("message", "Not found"),
            "authorization_warning": AUTH_WARNING,
        }

    user_data = data.get("data", {}).get("data", [{}])[0] if data.get("data") else {}
    name_info = user_data.get("name", {})
    addresses = user_data.get("addresses", [{}])
    phones = user_data.get("phones", [{}])
    internet_addresses = user_data.get("internetAddresses", [])

    first_phone = phones[0] if phones else {}
    first_address = addresses[0] if addresses else {}

    return {
        "phone": phone,
        "found": True,
        "name": f"{name_info.get('first', '')} {name_info.get('last', '')}".strip(),
        "carrier": first_phone.get("carrier", "Unknown"),
        "phone_type": first_phone.get("type", "Unknown"),
        "country_code": first_phone.get("countryCode", ""),
        "number_type": first_phone.get("numberType", ""),
        "spam_score": user_data.get("spamInfo", {}).get("spamScore", 0),
        "spam_type": user_data.get("spamInfo", {}).get("spamType", ""),
        "is_spam": user_data.get("spamInfo", {}).get("isSpam", False),
        "city": first_address.get("city", ""),
        "country": first_address.get("countryCode", ""),
        "internet_addresses": [
            {"id": ia.get("id"), "service": ia.get("service"), "caption": ia.get("caption")}
            for ia in internet_addresses[:5]
        ],
        "tags": user_data.get("tags", []),
        "authorization_warning": AUTH_WARNING,
    }


def _mock_result(phone: str, country_code: str) -> dict:
    return {
        "phone": phone,
        "country_code": country_code,
        "found": True,
        "name": "John Doe",
        "carrier": "Jio Telecom",
        "phone_type": "mobile",
        "number_type": "MOBILE",
        "spam_score": 12,
        "spam_type": "TELE_MARKETING",
        "is_spam": False,
        "city": "Mumbai",
        "country": "IN",
        "internet_addresses": [
            {"id": "johndoe@gmail.com", "service": "google", "caption": "John Doe"},
        ],
        "tags": [],
        "mock": True,
        "authorization_warning": AUTH_WARNING,
    }


def analyze(results: dict) -> dict:
    """Assess risk level based on Truecaller data."""
    spam_score = results.get("spam_score", 0)
    is_spam = results.get("is_spam", False)

    if spam_score >= 70 or is_spam:
        risk = "HIGH"
        note = "High spam score — likely spam/scam caller"
    elif spam_score >= 30:
        risk = "MEDIUM"
        note = "Moderate spam activity detected"
    else:
        risk = "LOW"
        note = "No significant spam activity"

    return {
        "risk": risk,
        "spam_score": spam_score,
        "is_spam": is_spam,
        "note": note,
    }


def report(results: dict) -> str:
    lines = [f"Truecaller Intelligence Report — {results.get('phone', 'N/A')}\n"]
    lines.append(f"  Name:       {results.get('name', 'Unknown')}")
    lines.append(f"  Carrier:    {results.get('carrier', 'N/A')}")
    lines.append(f"  Location:   {results.get('city', 'N/A')}, {results.get('country', 'N/A')}")
    lines.append(f"  Spam Score: {results.get('spam_score', 0)}")
    lines.append(f"  Is Spam:    {results.get('is_spam', False)}")
    if results.get("internet_addresses"):
        lines.append("  Online Profiles:")
        for ia in results["internet_addresses"]:
            lines.append(f"    [{ia.get('service', '').upper()}] {ia.get('caption', '')} — {ia.get('id', '')}")
    return "\n".join(lines)
