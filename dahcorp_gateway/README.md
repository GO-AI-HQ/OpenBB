# DAHCorp OpenBB Gateway

A narrow Cloud Run gateway for DAHCorp Finance. It exposes only three read-only market-data operations and uses the gateway service's attached Google identity to invoke the private OpenBB Cloud Run service.

## Public surface

- `GET /health` — no secret required; returns only service health.
- `GET /v1/quote` — requires `X-DAHCORP-GATEWAY-SECRET`.
- `GET /v1/history` — requires `X-DAHCORP-GATEWAY-SECRET`.
- `GET /v1/dividends` — requires `X-DAHCORP-GATEWAY-SECRET`.

Only the `yfinance` OpenBB provider is accepted. The gateway is not a generic proxy.

## Required runtime configuration

- `OPENBB_UPSTREAM_URL` — private OpenBB Cloud Run service URL.
- `OPENBB_UPSTREAM_AUDIENCE` — normally the same private Cloud Run service URL.
- `DAHCORP_GATEWAY_SECRET` — high-entropy app-to-app secret. Prefer mounting from Google Secret Manager.
- `OPENBB_MARKET_PROVIDER=yfinance`

## Google IAM

Attach the dedicated DAHCorp service account to this gateway Cloud Run service. That service account must have `roles/run.invoker` on the private OpenBB service.

The gateway obtains a short-lived Google ID token from the Cloud Run metadata server using the private OpenBB URL as its audience. No Google service-account JSON key is required.

## Container build

Build context is the repository root:

```bash
gcloud builds submit \
  --tag REGION-docker.pkg.dev/PROJECT_ID/REPOSITORY/dahcorp-openbb-gateway:latest \
  -f dahcorp_gateway/Dockerfile .
```

Deploy the resulting image as a separate Cloud Run service. The gateway Cloud Run service can allow unauthenticated ingress because application requests are separately authenticated by the DAHCorp gateway secret; the upstream OpenBB service remains private.

For production, store `DAHCORP_GATEWAY_SECRET` in Secret Manager and expose it to this service as an environment secret rather than putting the secret in source or a build command.
