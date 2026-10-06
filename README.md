# Current handoff (October 5, 2026)

The authoritative current status and exact Fly.io account/billing action are in ../Frontline-V1-progress.md. This package is scanner 1.0.1. fly.toml is a prepared template, not a deployed application. Deleted/expired jobs keep minimal request tombstones indefinitely to prevent reruns; report evidence expires after seven days. Raw DNS policy and web header values are omitted from retained evidence. Seven test groups pass. The notes below describe the recovered October 4 baseline; the current handoff supersedes conflicting retention and test-count statements.

# Frontline V1 scanner — deployment handoff

Built for Base44 app `6ab04df4b7345d43a3caf080`. No live scan, cloud deployment, token creation, customer PDF or delivery has occurred. Website publishing is not required and remains prohibited for this task.

## Remaining human boundary

No accessible AWS, Azure, Google Cloud, Fly, Railway or Wrangler configuration/CLI was found on the local machine; no cloud-related environment variable names were found. This does not establish that the owner has no cloud account. The Base44 sandbox is an app-development environment, not a persistent host for this Node scanner.

1. Tell Codex the cloud provider/project you already use, and sign in to that provider on this computer. Do not paste credentials into chat.
2. If you have no cloud account, choose a provider that runs Docker containers with public HTTPS and a persistent writable volume. Create/sign in to that account and complete its billing prompts yourself. Tell Codex the provider and project name; Codex can then prepare the exact provider configuration.
3. Approve any new hosting spend in that provider. Provider, account creation and billing decisions have not been made on your behalf.

## Deployment requirements

Use Node 24 or the included Dockerfile. Deploy **one replica** with a persistent private volume mounted at `/data`, HTTPS termination, no public access to the volume, and no request/Authorization-header logging. Do not use ephemeral/serverless storage or multiple replicas for this SQLite V1. Container port: 8080. Limit inbound connections and requests at the hosting proxy; set a maximum request body of 4096 bytes and header size of 8 KB. The API intentionally has no CORS.

Environment variables:

- `FRONTLINE_ALLOWED_HOSTS=frontlineconsultant.com` (only authorized validation hostname).
- `FRONTLINE_DB_PATH=/data/frontline.sqlite`.
- `FRONTLINE_API_TOKEN`: create a cryptographically random 32-byte secret in the provider's secret manager (64 hex characters is suitable). Do not print it or commit it. Copy it privately to Base44 secret storage, using the same value in both places. No token has been generated in this package.

Once deployed, set Base44 backend secrets:

- `FRONTLINE_API_URL=https://<assigned-scanner-host>` — origin only, no endpoint path, query or credentials.
- `FRONTLINE_API_TOKEN` — the matching private token.

The bridge's `status` action now calls authenticated `/v1/health`; it reports connected only after a successful ready response, without starting a scan.

## Contract

Every endpoint requires `Authorization: Bearer <token>`, `X-Frontline-Principal` (staff ID), and `X-Frontline-Role: admin`. These principal claims are trusted only because the secret is exclusively held by the Base44 staff bridge. Health reveals no secrets.

- `GET /v1/health`: `{status:"ok", ready:true, scanner_version, report_version}`.
- `POST /v1/assessments`: headers `Idempotency-Key` and `X-Frontline-Request-ID`; body `{target,email_domain:null|target,authorization_confirmed:true}`. Returns 202 and `{assessment_id,request_id,target,status:"queued"}`; same key/request/principal/scope returns original assessment. Conflicting reuse returns 409.
- `GET /v1/assessments/<UUID>`: owner-scoped job; on completion, `result` contains the report, whose `result` contains the unchanged FERI-0.1 scoring output. This matches SecuritySnapshotV1 and exportScanReport.
- `DELETE /v1/assessments/<UUID>`: staff-owner deletion after completion/failure.

Errors contain `error` and `code`: 400 malformed request, 401 authentication, 403 scope/staff, 404 absent/other-owner job, 409 conflicting key/active deletion, 413 size, 429 quota/capacity, 500 internal. Scan failures remain in the original job; no automatic scan reruns. Transport retry budget is zero. Base44 can retry submission with its original key; frontend status polling is already bounded.

## Safety and limits

Explicit exact-host allowlist plus staff authorization record in Base44. DNS IPv4 addresses are checked before any connection; private/reserved addresses and all IPv6 are rejected. A checked public IPv4 address is pinned into HTTP/TLS connections, with original hostname/SNI and trusted certificate verification. Only ports 80/443 and path `/` are requested. Redirects are observed, never followed. Up to one HTTP and one HTTPS GET per scan; at most 64 KB body received, none stored. Five-second network timeouts; 25-second overall scan abort. One active worker and 20 accepted jobs per rolling day, enforced in SQLite transaction. Idempotency persists across restarts; interrupted jobs become failed rather than automatically rescanned.

DNS requests are limited to target A and, if the actual sending domain is confirmed, target TXT and `_dmarc.<target>` TXT. SPF includes, DKIM selectors, DMARC organizational fallback and unrelated DNS hosts are never followed. SPF/DMARC discovery is partial evidence rather than a claim of full policy validation. No CSP meta inspection or exhaustive TLS protocol/cipher enumeration; limitations are attached to results. No crawl, credentials, payloads, exploitation or port scanning. Missing evidence suppresses the score under the original model.

Reports and minimal ID-only audit records currently expire after seven days; this is a proposed operational default requiring owner acceptance before deployment. SQLite WAL/backups/hosting logs need the same retention and privacy settings. Base44 request records, written authorization, PDFs and delivery records have separate retention duties. Deletion removes report evidence; a tombstone prevents accidental rerun within retention. Do not deliver an illustrative report.

## Resume the existing request

`6ac2e5f23f27e08217e5f34e` was verified in Base44 as `authorized`, target `frontlineconsultant.com`, with persisted staff authorization. It has no scan key or assessment ID. After deployment and successful bridge health check, select that existing request in the unpublished staff preview, confirm exact scope, and start once. Leave email domain unknown unless its actual sending-domain role is confirmed. Preserve the generated scan key on retries. Review live report evidence, export and visually inspect the real PDF, then deliver only through the previously agreed private channel to a verified recipient and record the actual delivery reference. No delivery recipient/channel has been independently verified in this turn.

## Verification recorded so far

Local tests use mocked scan observations and no external target traffic. Authentication, health-without-scan, exact host/email scope, request-ID validation, principal ownership, replay/conflict behavior, completed report shape, deletion and unknown-score suppression pass. DNS/IP and redirect guard tests pass. Deployment, HTTPS proxy, real DNS/TLS/root observations, real report/PDF/delivery remain UNVERIFIED until a cloud target is available.

Run `npm test` to repeat local verification.

