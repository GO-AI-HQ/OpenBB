import asyncio
import base64
import csv
import io
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
_ALLOWED_MARKET_PROVIDER = {"yfinance"}
_ALLOWED_MACRO_PROVIDER = {"econdb"}
_ALLOWED_CALENDAR_PROVIDER = {"fred"}
_SYMBOL_RE = re.compile(r"^[A-Za-z0-9.^=_-]{1,24}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_COUNTRY_RE = re.compile(r"^[A-Za-z0-9_*,.-]{1,80}$")
_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_METADATA_IDENTITY_URL = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
_FRED_GRAPH_URL = "https://fred.stlouisfed.org/graph/fredgraph.csv"
_ALLOWED_FRED_SERIES = {
    "FEDFUNDS",      # Fed funds rate
    "DGS2",          # 2Y Treasury
    "DGS10",         # 10Y Treasury
    "T10Y2Y",        # 10Y-2Y curve
    "CPIAUCSL",      # CPI
    "PCEPI",         # PCE price index
    "UNRATE",        # unemployment
    "PAYEMS",        # nonfarm payrolls
    "INDPRO",        # industrial production
    "RSAFS",         # retail sales
    "VIXCLS",        # VIX
    "BAMLH0A0HYM2",  # high-yield option-adjusted spread
    "NFCI",          # Chicago Fed financial conditions
    "DTWEXBGS",      # broad dollar index
}

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


def _validate_provider(provider: str | None, allowed: set[str], default: str) -> str:
    resolved = (provider or default).strip().lower()
    if resolved not in allowed:
        raise HTTPException(status_code=400, detail="Provider is not allowed by this gateway.")
    return resolved


def _validate_date(value: str) -> str:
    if not _DATE_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid date.")
    return value


def _validate_country(value: str) -> str:
    if not _COUNTRY_RE.fullmatch(value):
        raise HTTPException(status_code=400, detail="Invalid country selector.")
    return value


def _validate_fred_series(raw: str) -> list[str]:
    series = [item.strip().upper() for item in raw.split(",") if item.strip()]
    unique = list(dict.fromkeys(series))
    if not unique or len(unique) > 14 or any(item not in _ALLOWED_FRED_SERIES for item in unique):
        raise HTTPException(status_code=400, detail="FRED series is not approved by this gateway.")
    return unique


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


async def _fred_series(series: list[str], start_date: str, end_date: str) -> Response:
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        for series_id in series:
            response = await client.get(
                _FRED_GRAPH_URL,
                params={"id": series_id, "cosd": start_date, "coed": end_date},
                headers={"Accept": "text/csv"},
            )
            if response.status_code != 200:
                raise HTTPException(status_code=502, detail=f"FRED series {series_id} was unavailable.")
            reader = csv.DictReader(io.StringIO(response.text))
            observations = []
            for row in reader:
                date = str(row.get("DATE") or row.get("observation_date") or "")
                raw = row.get(series_id)
                if not date or raw in (None, "", "."):
                    continue
                try:
                    value = float(raw)
                except (TypeError, ValueError):
                    continue
                observations.append({"date": date, "value": value})
            results.append({"series": series_id, "observations": observations})
    return Response(
        content=json.dumps({"provider": "fred", "results": results}),
        media_type="application/json",
    )


def _auth(
    request: Request,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
) -> None:
    _require_signed_request(request, timestamp, nonce, signature)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "fabric": "v2"}


@app.get("/v1/quote")
async def quote(
    request: Request,
    symbol: str = Query(...),
    provider: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/price/quote",
        {"symbol": _validate_symbols(symbol), "provider": _validate_provider(provider, _ALLOWED_MARKET_PROVIDER, OPENBB_MARKET_PROVIDER)},
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
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/price/historical",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": _validate_date(start_date),
            "end_date": _validate_date(end_date),
            "interval": "1d",
            "provider": _validate_provider(provider, _ALLOWED_MARKET_PROVIDER, OPENBB_MARKET_PROVIDER),
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
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/fundamental/dividends",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": _validate_date(start_date),
            "end_date": _validate_date(end_date),
            "provider": _validate_provider(provider, _ALLOWED_MARKET_PROVIDER, OPENBB_MARKET_PROVIDER),
        },
    )


@app.get("/v2/profile")
async def profile(
    request: Request,
    symbol: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/profile",
        {"symbol": _validate_symbols(symbol), "provider": "yfinance"},
    )


@app.get("/v2/index/history")
async def index_history(
    request: Request,
    symbol: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/index/price/historical",
        {
            "symbol": _validate_symbols(symbol),
            "start_date": _validate_date(start_date),
            "end_date": _validate_date(end_date),
            "interval": "1d",
            "provider": "yfinance",
        },
    )


@app.get("/v2/index/available")
async def index_available(
    request: Request,
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy("/api/v1/index/available", {"provider": "yfinance", "use_cache": "true"})


@app.get("/v2/macro/indicators")
async def macro_indicators(
    request: Request,
    symbol: str = Query("main"),
    country: str = Query("US"),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    params: dict[str, Any] = {
        "symbol": symbol.strip()[:80] or "main",
        "country": _validate_country(country),
        "provider": "econdb",
    }
    if start_date:
        params["start_date"] = _validate_date(start_date)
    if end_date:
        params["end_date"] = _validate_date(end_date)
    return await _proxy("/api/v1/economy/indicators", params)


@app.get("/v2/macro/calendar")
async def macro_calendar(
    request: Request,
    start_date: str = Query(...),
    end_date: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/economy/calendar",
        {
            "start_date": _validate_date(start_date),
            "end_date": _validate_date(end_date),
            "provider": "fred",
        },
    )


@app.get("/v2/fred/series")
async def fred_series(
    request: Request,
    series: str = Query(...),
    start_date: str = Query(...),
    end_date: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _fred_series(
        _validate_fred_series(series),
        _validate_date(start_date),
        _validate_date(end_date),
    )
