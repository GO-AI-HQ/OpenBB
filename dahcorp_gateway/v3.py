import re
from typing import Any

from fastapi import Header, HTTPException, Query, Request, Response

from main import app, _auth, _proxy, _validate_country, _validate_date, _validate_symbols

# Intelligence Fabric v3 adds narrowly allowlisted, read-only research routes on
# top of the already-deployed signed v2 gateway. No brokerage or execution
# endpoint is proxied from this service.
_CHOKEPOINTS = {
    "suez_canal",
    "panama_canal",
    "bab_el_mandeb_strait",
    "malacca_strait",
    "strait_of_hormuz",
    "cape_of_good_hope",
    "taiwan_strait",
    "gibraltar_strait",
}
_EIA_CATEGORIES = {
    "balance_sheet",
    "inputs_and_production",
    "crude_petroleum_stocks",
    "gasoline_fuel_stocks",
    "distillate_fuel_oil_stocks",
    "imports",
    "weekly_estimates",
    "spot_prices_crude_gas_heating",
}
_EIA_STEO_TABLES = {"01", "02", "03a", "03b", "04a", "04b", "04c", "04d"}
_QUERY_RE = re.compile(r"^[A-Za-z0-9 .,&'()/_+-]{1,80}$")
_CODE_RE = re.compile(r"^[A-Za-z0-9_.:-]{2,48}$")


def _validate_chokepoints(raw: str) -> str:
    values = [item.strip().lower() for item in raw.split(",") if item.strip()]
    unique = list(dict.fromkeys(values))
    if not unique or len(unique) > 8 or any(item not in _CHOKEPOINTS for item in unique):
        raise HTTPException(status_code=400, detail="Chokepoint selector is not approved by this gateway.")
    return ",".join(unique)


def _validate_query(value: str) -> str:
    cleaned = value.strip()
    if not _QUERY_RE.fullmatch(cleaned):
        raise HTTPException(status_code=400, detail="Invalid research query.")
    return cleaned


def _validate_code(value: str) -> str:
    cleaned = value.strip()
    if not _CODE_RE.fullmatch(cleaned):
        raise HTTPException(status_code=400, detail="Invalid market code.")
    return cleaned


def _bounded_limit(value: int, ceiling: int = 100) -> int:
    if value < 1 or value > ceiling:
        raise HTTPException(status_code=400, detail="Invalid result limit.")
    return value


def _headers_auth(
    request: Request,
    timestamp: str | None,
    nonce: str | None,
    signature: str | None,
) -> None:
    _auth(request, timestamp, nonce, signature)


@app.get("/v3/health")
async def v3_health() -> dict[str, str]:
    return {"status": "ok", "fabric": "v3"}


@app.get("/v3/options/chains")
async def options_chains(
    request: Request,
    symbol: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/derivatives/options/chains",
        {
            "symbol": _validate_symbols(symbol),
            "provider": "yfinance",
            "moneyness": "all",
            "use_cache": "true",
        },
    )


@app.get("/v3/fund/nport")
async def fund_nport(
    request: Request,
    symbol: str = Query(...),
    year: int | None = Query(None),
    quarter: int | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    params: dict[str, Any] = {
        "symbol": _validate_symbols(symbol),
        "provider": "sec",
        "use_cache": "true",
    }
    if year is not None:
        if year < 2000 or year > 2100:
            raise HTTPException(status_code=400, detail="Invalid reporting year.")
        params["year"] = year
    if quarter is not None:
        if quarter not in {1, 2, 3, 4}:
            raise HTTPException(status_code=400, detail="Invalid reporting quarter.")
        params["quarter"] = quarter
    return await _proxy("/api/v1/etf/nport_disclosure", params)


@app.get("/v3/shipping/chokepoints")
async def shipping_chokepoints(
    request: Request,
    chokepoint: str = Query("strait_of_hormuz,suez_canal,bab_el_mandeb_strait,panama_canal,cape_of_good_hope,taiwan_strait"),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    params: dict[str, Any] = {"chokepoint": _validate_chokepoints(chokepoint), "provider": "imf"}
    if start_date:
        params["start_date"] = _validate_date(start_date)
    if end_date:
        params["end_date"] = _validate_date(end_date)
    return await _proxy("/api/v1/economy/shipping/chokepoint_volume", params)


@app.get("/v3/shipping/ports")
async def shipping_ports(
    request: Request,
    country: str = Query("USA"),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    params: dict[str, Any] = {"country": _validate_country(country), "provider": "imf"}
    if start_date:
        params["start_date"] = _validate_date(start_date)
    if end_date:
        params["end_date"] = _validate_date(end_date)
    return await _proxy("/api/v1/economy/shipping/port_volume", params)


@app.get("/v3/energy/petroleum")
async def petroleum_status(
    request: Request,
    category: str = Query("weekly_estimates"),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    resolved = category.strip().lower()
    if resolved not in _EIA_CATEGORIES:
        raise HTTPException(status_code=400, detail="EIA category is not approved by this gateway.")
    params: dict[str, Any] = {"category": resolved, "provider": "eia"}
    if start_date:
        params["start_date"] = _validate_date(start_date)
    if end_date:
        params["end_date"] = _validate_date(end_date)
    return await _proxy("/api/v1/commodity/petroleum_status_report", params)


@app.get("/v3/energy/steo")
async def short_term_energy_outlook(
    request: Request,
    table: str = Query("01"),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    resolved = table.strip().lower()
    if resolved not in _EIA_STEO_TABLES:
        raise HTTPException(status_code=400, detail="EIA STEO table is not approved by this gateway.")
    params: dict[str, Any] = {"table": resolved, "provider": "eia"}
    if start_date:
        params["start_date"] = _validate_date(start_date)
    if end_date:
        params["end_date"] = _validate_date(end_date)
    return await _proxy("/api/v1/commodity/short_term_energy_outlook", params)


@app.get("/v3/cftc/search")
async def cftc_search(
    request: Request,
    query: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/cftc/cot_search",
        {"query": _validate_query(query), "provider": "cftc", "report_type": "legacy"},
    )


@app.get("/v3/cftc/cot")
async def cftc_cot(
    request: Request,
    code: str = Query(...),
    limit: int = Query(4),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/cftc/cot",
        {
            "code": _validate_code(code),
            "limit": _bounded_limit(limit, 20),
            "provider": "cftc",
            "report_type": "legacy",
            "measure": "all",
        },
    )


@app.get("/v3/sec/insiders")
async def sec_insiders(
    request: Request,
    symbol: str = Query(...),
    limit: int = Query(40),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/ownership/insider_trading",
        {"symbol": _validate_symbols(symbol), "limit": _bounded_limit(limit), "provider": "sec"},
    )


@app.get("/v3/sec/mdna")
async def sec_mdna(
    request: Request,
    symbol: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/fundamental/management_discussion_analysis",
        {
            "symbol": _validate_symbols(symbol),
            "provider": "sec",
            "include_tables": "false",
            "raw_html": "false",
            "use_cache": "true",
        },
    )


@app.get("/v3/short-interest")
async def short_interest(
    request: Request,
    symbol: str = Query(...),
    x_dahcorp_timestamp: str | None = Header(None),
    x_dahcorp_nonce: str | None = Header(None),
    x_dahcorp_signature: str | None = Header(None),
) -> Response:
    _headers_auth(request, x_dahcorp_timestamp, x_dahcorp_nonce, x_dahcorp_signature)
    return await _proxy(
        "/api/v1/equity/shorts/short_interest",
        {"symbol": _validate_symbols(symbol), "provider": "finra"},
    )
