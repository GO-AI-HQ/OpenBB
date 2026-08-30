import asyncio
import base64
import json
import os
import re
import time
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response

app = FastAPI(title="DAHCorp OpenBB Gateway", docs_url=None, redoc_url=None, openapi_url=None)

_DEFAULT_OPENBB_UPSTREAM = "https://dahcorp-openbb-780616243826.us-east1.run.app"
OPENBB_UPSTREAM_URL = os.environ.get("OPENBB_UPSTREAM_URL", _DEFAULT_OPENBB_UPSTREAM).rstrip("/")
OPENBB_UPSTREAM_AUDIENCE = os.environ.get("OPENBB_UPSTREAM_AUDIENCE", OPENBB_UPSTREAM_URL).rstrip("/")
OPENBB_MARKET_PROVIDER = os.environ.get("OPENBB_MARKET_PROVIDER", "yfinance").strip().lower() or "yfinance"

# Public verification key only. The matching private key exists solely in the
# DAHCorp Netlify runtime and is never stored in Google Cloud or this repository.
_DAHCORP_PUBLIC_KEY_B64 = "MCowBQYDK2VwAyEAwNJTos3oOOctKRgte0aIaLLiyen+uekLhZKJt/IJch0="
_ALLOWED_PROVIDER = {"yfinance"}
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9.^=_-]{1,24}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)

_token_lock = asyncio.Lock()
_cached_token: tuple[str, int] | None = None
_seen_nonces: dict[str, int] = {}
_public_key = serialization.load_der_public_key(base64.b64decode(_DAHCORP_PUBLIC_KEY_B64))
if not isinstance(_public_key, Ed25519PublicKey):
    raise RuntimeError("DAHCorp gateway verification key is not Ed25519.")


def _validate_symbols(raw: str) -> str:
    symbols = [item.strip().upper() for item in raw.split(",") if item.strip()]
    if not symbols or len(symbols) > 50 or any(not _SYMBOL_RE.fullmatch(symbol) for symbol in symbols):
        raise HTTPException(status_code=400, detail="Invalid symbol list.")
    return ",".join(dict.fromkeys(symbols))


def _validate_provider(provider: str | None) -> str:
    resolved = (provider or OPENBB_MARKET_PROVIDER).strip().lower()
    if resolved not in _ALLOWED_PROVIDER:
        raise HTTPException(status_code=400, detail="Provider is not allowed by this gateway.")
    return resolved


def _decode_base64url(value: str) -> bytes:
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _require_signed_request(
    request: Request,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
) -> None:
    if not timestamp or not nonce or not signature or not _NONCE_RE.fullmatch(nonce):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    try:
        request_time = int(timestamp)
    except ValueError as exc:
        raise HTTPException(status_code=401, detail="Unauthorized.") from exc

    now = int(time.time())
    if abs(now - request_time) > 90:
        raise HTTPException(status_code=401, detail="Unauthorized.")

    # Best-effort replay protection per warm Cloud Run instance. HTTPS plus the
    # 90-second signed timestamp window remains authoritative across instances.
    for seen, seen_at in list(_seen_nonces.items()):
        if now - seen_at > 120:
            _seen_nonces.pop(seen, None)
    if nonce in _seen_nonces:
        raise HTTPException(status_code=409, detail="Duplicate request.")

    canonical = "\n".join([
        request.method.upper(),
        request.url.path,
        request.url.query,
        timestamp,
        nonce,
    ])
    try:
        _public_key.verify(_decode_base64url(signature), canonical.encode("utf-8"))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Unauthorized.") from exc
    _seen_nonces[nonce] = now


def _jwt_exp(token: str) -> int:
    try:
        payload = token.split(".")[1]
        payload += "=" * ((4 - len(payload) % 4) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")))
        exp = decoded.get("exp")
        return int(exp) if isinstance(exp, (int, float)) else 0
    except Exception:
        return 0


async def _identity_token() -> str:
    global _cached_token
    now = int(time.time())
    if _cached_token and _cached_token[1] - 60 > now:
        return _cached_token[0]

    async with _token_lock:
        now = int(time.time())
        if _cached_token and _cached_token[1] - 60 > now:
            return _cached_token[0]

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                _METADATA_IDENTITY_URL,
                params={"audience": OPENBB_UPSTREAM_AUDIENCE, "format": "full"},
                headers={"Metadata-Flavor": "Google"},
            )
        if response.status_code != 200:
            raise HTTPException(status_code=502, detail="Could not obtain Google workload identity.")
        token = response.text.strip()
        if not token:
            raise HTTPException(status_code=502, detail="Google workload identity token was empty.")
        _cached_token = (token, _jwt_exp(token) or now + 300)
        return token


async def _proxy(path: str, params: dict[str, Any]) -> Response:
    token = await _identity_token()
    async with httpx.AsyncClient(timeout=30.0) as client:
        upstream = await client.get(
            f"{OPENBB_UPSTREAM_URL}{path}",
            params=params,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
    content_type = upstream.headers.get("content-type", "application/json")
    return Response(content=upstream.content, status_code=upstream.status_code, media_type=content_type.split(";")[0])


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/v1/quote")
async def quote(
    request: Request,
    symbol: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _require_signed_request(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/price/quote",
        {"symbol": _validate_symbols(symbol), "provider": _validate_provider(provider)},
    )


@app.get("/v1/history")
async def history(
    request: Request,
    symbol: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _require_signed_request(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/price/historical",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": start_date,
            "end_date": end_date,
            "interval": "1d",
            "provider": _validate_provider(provider),
        },
    )


@app.get("/v1/dividends")
async def dividends(
    request: Request,
    symbol: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _require_signed_request(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/fundamental/dividends",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": start_date,
            "end_date": end_date,
            "provider": _validate_provider(provider),
        },
    )
