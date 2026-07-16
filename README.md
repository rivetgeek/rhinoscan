# RhinoScan — Gray Rhino Security

Security assessment platform combining open-source scanners with proprietary
checks. One scan model: pick targets (AWS profiles, GitHub orgs) and engines,
findings from every engine land in a unified table with deterministic ids for
delta tracking, and everything is exportable to Hephaestus as versioned NDJSON.

**Engines**

| Engine | Origin | Target | What it does |
|--------|--------|--------|--------------|
| baseline | Baseline | AWS profile | RhinoScan's proprietary read-only boto3 check battery |
| prowler-aws | Prowler | AWS profile | Prowler cloud benchmark (failed checks roll up) |
| prowler-github | GitHub | GitHub org | Prowler GitHub-provider benchmark |
| trufflehog | Secrets | GitHub org | Secret scanning + IAM exposure correlation |
| scorecard | Scorecard | GitHub org | OpenSSF Scorecard supply-chain posture |

Profiles come straight from your `~/.aws/config` — there are no role ARNs to
paste in. Credential chains (SSO, `source_profile`, `role_arn`, `aws login`)
resolve exactly as your CLI does. GitHub engines reuse your `gh auth login`
token (or `GH_TOKEN`/`GITHUB_TOKEN`).

## Prerequisites

- Docker + Docker Compose
- A working `~/.aws/config` with profiles for the client accounts you assess.
  Each profile needs read-only access (the AWS-managed `SecurityAudit` +
  `ViewOnlyAccess` / `IAMReadOnlyAccess` policies are sufficient).
- (Optional) `gh auth login` for GitHub-side engines

## Setup

```bash
git clone <repo>
cd rhinoscan
cp .env.example .env

# Required: absolute host path to the data directory (used by scan containers)
echo "HOST_DATA_DIR=$(pwd)/data" >> .env

docker compose up -d --build
```

Open http://localhost:3000 — ports bind to 127.0.0.1 only. Verify with
`curl http://localhost:8000/health`.

## Usage

1. **Assess** — pick AWS profiles and/or a GitHub org, tick engines, scan.
   Runs show per-engine status; open one for engine-level detail tabs and the
   markdown report download.
2. **Dashboard** — unified findings across all targets, filterable by
   source/category/severity, with description + remediation + the exact AWS
   API call behind each finding. The Export button downloads the Hephaestus
   NDJSON.

Regional checks default to `us-west-2`; set `AWS_DEFAULT_REGION` to change it.
Multi-region is a follow-on.

## API (v1)

```
GET  /api/v1/profiles                    # scannable AWS profiles
GET  /api/v1/engines                     # available scanner adapters
POST /api/v1/scans                       # { targets: [...], engines: [...] } → run ids
GET  /api/v1/scans                       # list runs
GET  /api/v1/scans/{run_id}              # run + per-engine status
GET  /api/v1/scans/{run_id}/prowler      # raw Prowler results (?provider=aws|github)
GET  /api/v1/scans/{run_id}/secrets      # raw TruffleHog hits
GET  /api/v1/scans/{run_id}/scorecard    # per-repo Scorecard detail
GET  /api/v1/scans/{run_id}/alerts       # correlated credential-exposure alerts
GET  /api/v1/findings                    # unified findings — ?target= &severity= &category= &origin= &run_id=, paginated
GET  /api/v1/findings/summary            # counts by severity/category/origin
GET  /api/v1/report/{run_id}             # markdown report
GET  /api/v1/export                      # Hephaestus NDJSON — ?since= &target= &include_raw=
```

### Auth

Set `RHINOSCAN_API_TOKEN` in `.env` to require `Authorization: Bearer <token>`
on `/api/v1`. nginx injects the header server-side for the UI, so the browser
never handles the token. Unset, auth is disabled — acceptable only because
compose binds to localhost.

### Hephaestus export

`GET /api/v1/export` streams `rhinoscan.export.v1` NDJSON: an envelope line
(run metadata) followed by one line per finding. Finding ids are deterministic
hashes of target+check+resource, so ingestion is an idempotent upsert and a
finding absent from a later full export for the same target has been resolved.

## Data

Everything lives in `./data/` (gitignored except scaffolding):

- `./data/db/rhino.db` — SQLite (runs, unified findings, engine raw detail)
- `./data/scans/<run-id>/` — raw Prowler + TruffleHog output files

## Architecture

```
React (3000) → nginx (injects bearer) → FastAPI /api/v1 (8000)
                                           │
                                        runner ─ one run per target
                                           │
                             ┌─ adapters (ScannerAdapter contract) ─┐
                             │ baseline      in-process boto3       │
                             │ prowler-aws   docker sibling         │
                             │ prowler-github docker sibling        │
                             │ trufflehog    docker sibling + corr. │
                             │ scorecard     docker sibling per repo│
                             └──────────────┬──────────────────────┘
                                            ▼
                              findings (unified, deterministic ids)
                                            ▼
                              /api/v1/export → Hephaestus
```

Adapters emit into the unified `findings` table (origin-tagged, pruned
per-origin on re-scan so the dashboard shows current posture); engine tables
(`prowler_findings`, `truffle_findings`, `scorecard_findings`) keep raw detail
for the run views. Adding a scanner = adding one adapter — no new tables,
endpoints, or pages.

The backend mounts `~/.aws` read-only and resolves each profile's credential
chain itself (AWS CLI `export-credentials`, boto3 fallback), passing only
short-lived keys into scanner containers. `HOST_DATA_DIR` must point at
`./data` on the host so sibling containers can write scan output.

## Roadmap

- Hephaestus-side ingestion of the export
- PDF report generation (Gray Rhino branded)
- Semgrep adapter (static analysis)
- Multi-region support
- Executive narrative via Claude API
