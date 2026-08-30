import asyncio
import base64
import hmac
import json
import os
import re
import time
from typing import Any

import httpx
from fastapi import FastAPI, Header, HTTPException, Query, Response

app = FastAPI(title="DAHCorp OpenBB Gateway", docs_url=None, redoc_url=None, openapi_url=None)

OPENBB_UPSTREAM_URL = os.environ.get("OPENBB_UPSTREAM_URL", "").rstrip("/")
OPENBB_UPSTREAM_AUDIENCE = os.environ.get("OPENBB_UPSTREAM_AUDIENCE", OPENBB_UPSTREAM_URL).rstrip("/")
DAHCORP_GATEWAY_SECRET = os.environ.get("DAHCORP_GATEWAY_SECRET", "")
OPENBB_MARKET_PROVIDER = os.environ.get("OPENBB_MARKET_PROVIDER", "yfinance").strip().lower() or "yfinance"

_ALLOWED_PROVIDER = {"yfinance"}
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9.^=_-]{1,24}$")
_METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)

_token_lock = asyncio.Lock()
_cached_token: tuple[str, int] | None = None


def _require_config() -> None:
    if not OPENBB_UPSTREAM_URL or not OPENBB_UPSTREAM_AUDIENCE or not DAHCORP_GATEWAY_SECRET:
        raise HTTPException(status_code=503, detail="Gateway is not fully configured.")


def _authorized(candidate: str | None) -> bool:
    if not candidate or not DAHCORP_GATEWAY_SECRET:
        return False
    return hmac.compare_digest(candidate.encode("utf-8"), DAHCORP_GATEWAY_SECRET.encode("utf-8"))


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
    _require_config()
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
    symbol: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_gateway_secret: str | None = Header(None),
) -> Response:
    if not _authorized(x_dahcorp_gateway_secret):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    return await _proxy(
        "/api/v1/equity/price/quote",
        {"symbol": _validate_symbols(symbol), "provider": _validate_provider(provider)},
    )


@app.get("/v1/history")
async def history(
    symbol: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_gateway_secret: str | None = Header(None),
) -> Response:
    if not _authorized(x_dahcorp_gateway_secret):
        raise HTTPException(status_code=401, detail="Unauthorized.")
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
    symbol: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_gateway_secret: str | None = Header(None),
) -> Response:
    if not _authorized(x_dahcorp_gateway_secret):
        raise HTTPException(status_code=401, detail="Unauthorized.")
    return await _proxy(
        "/api/v1/equity/fundamental/dividends",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": start_date,
            "end_date": end_date,
            "provider": _validate_provider(provider),
        },
    )
