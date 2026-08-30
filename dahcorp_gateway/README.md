# DAHCorp OpenBB Gateway

A narrow Cloud Run gateway for DAHCorp Finance. It exposes only three read-only market-data operations and uses the gateway service's attached Google identity to invoke the private OpenBB Cloud Run service.

## Public surface

- `GET /health` — public health check only.
- `GET /v1/quote` — requires a valid DAHCorp Ed25519 request signature.
- `GET /v1/history` — requires a valid DAHCorp Ed25519 request signature.
- `GET /v1/dividends` — requires a valid DAHCorp Ed25519 request signature.

Only the `yfinance` OpenBB provider is accepted. The gateway is not a generic proxy.

## Authentication model

Netlify holds the Ed25519 **private signing key** in its encrypted environment. The gateway contains only the matching **public verification key**, which is safe to commit. Each request signs the HTTP method, path, exact query string, timestamp, and nonce. Requests outside a 90-second window or with an invalid signature are rejected.

No shared application secret and no Google service-account JSON key are required in Netlify.

## Runtime configuration

The service has a default upstream target for the current DAHCorp OpenBB Cloud Run deployment. These values remain overridable with:

- `OPENBB_UPSTREAM_URL` — private OpenBB Cloud Run service URL.
- `OPENBB_UPSTREAM_AUDIENCE` — normally the same private Cloud Run service URL.
- `OPENBB_MARKET_PROVIDER=yfinance`

## Google IAM

Attach the dedicated DAHCorp service account to this gateway Cloud Run service. That service account must have `roles/run.invoker` on the private OpenBB service.

The gateway obtains a short-lived Google ID token from the Cloud Run metadata server using the private OpenBB URL as its audience. No Google service-account JSON key is required.

## Container build

The `dahcorp_gateway` folder is a self-contained Cloud Run build context:

```bash
gcloud builds submit dahcorp_gateway \
  --tag REGION-docker.pkg.dev/PROJECT_ID/REPOSITORY/dahcorp-openbb-gateway:latest
```

Deploy the resulting image as a separate Cloud Run service and attach the dedicated DAHCorp service account. The gateway service may allow unauthenticated ingress because every market-data route independently requires a valid DAHCorp signature; the upstream OpenBB service remains private.
