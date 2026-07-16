# RhinoScan — Gray Rhino Security

AWS baseline security assessment platform. Runs a battery of nondestructive,
read-only AWS checks against configured client profiles, surfaces findings in a
dashboard, persists them in SQLite for delta tracking, and generates markdown
reports.

Profiles come straight from your `~/.aws/config` — there are no role ARNs to
paste in. RhinoScan creates a `boto3.Session(profile_name=...)` per profile and
lets boto3 resolve credentials (SSO, `source_profile`, `role_arn`, MFA) exactly
as the AWS CLI does. The legacy Prowler + TruffleHog credential-correlation
tooling still ships under **Prowler / Secrets** in the sidebar.

## Prerequisites

- Docker + Docker Compose
- A working `~/.aws/config` with profiles for the client accounts you assess.
  Each profile needs read-only access (e.g. the AWS-managed `SecurityAudit` +
  `ViewOnlyAccess` policies).
- (Optional) GitHub token with org repo read access for the legacy TruffleHog path

## RhinoScan baseline assessment

1. Start the stack (see Setup below). RhinoScan mounts `~/.aws` read-only.
2. Open http://localhost:3000 — the **Dashboard** loads.
3. Pick a profile (or **All profiles**) in the header source selector and click
   **Scan**. Profiles are read live from `GET /profiles` (excluding `default`
   and `grsconsultant`).
4. Findings stream into the table once the run completes; filter by category via
   the breakdown chart and expand a row for description + remediation.
5. Download a markdown report at `GET /report/{run_id}`.

Regional checks (GuardDuty, Security Hub, EC2, Lambda) default to `us-west-2`;
set `AWS_DEFAULT_REGION` to change it. Multi-region is a follow-on.

## Setup

```bash
git clone <repo>
cd rhino-scan
cp .env.example .env

# Required: absolute host path to the data directory (used by scan containers)
echo "HOST_DATA_DIR=$(pwd)/data" >> .env

# Optional: add AWS credentials if not using an instance profile
# echo "AWS_ACCESS_KEY_ID=..." >> .env
# echo "AWS_SECRET_ACCESS_KEY=..." >> .env

docker compose up -d --build
```

Open http://localhost:3000

Verify the stack is healthy:

```bash
curl http://localhost:8000/health
curl http://localhost:3000
```

## IAM permission requirements

Both the native check battery and the legacy Prowler path run against the
identity each `~/.aws/config` profile resolves to. That identity needs read-only
coverage — the AWS-managed `SecurityAudit` and `IAMReadOnlyAccess` (or
`ViewOnlyAccess`) policies are sufficient. Credential resolution (SSO,
`source_profile`, `role_arn`, MFA) is handled by boto3 from the profile chain;
there is no role ARN to paste in and no `sts:AssumeRole` policy to maintain on
the scanner side.

## Prowler / Secrets scan (legacy path)

1. Start the stack (above)
2. Open http://localhost:3000 → **Prowler / Secrets** → **New Scan**
3. Pick an **AWS profile** from the dropdown (sourced live from `~/.aws/config`)
   and a region
4. Leave GitHub fields blank to run Prowler only
5. Watch the job on the Scans page; open it when status is `complete`

RhinoScan resolves the selected profile's credential chain and passes the
resulting temporary credentials into the Prowler container — the container never
sees your `~/.aws` config. For GitHub secret scanning, also provide an org name
and a token with repo read access.

## Data

Everything lives in `./data/` (gitignored except directory scaffolding):

- `./data/db/rhino.db` — SQLite database
- `./data/scans/<job-id>/` — raw Prowler + TruffleHog JSON
- `./data/reports/` — reserved for V2 PDF reports

## Architecture

```
React (port 3000) → nginx → FastAPI (port 8000) → SQLite (findings, runs)
                                                 → boto3 native check battery
                                                   (per ~/.aws profile, read-only)

Legacy path (Prowler / Secrets tab):
                                                 → Docker: Prowler container
                                                 → Docker: TruffleHog container
                                                 → boto3: IAM correlation
```

RhinoScan's native checks run in-process via boto3 against each selected profile
— no containers, no static credentials. The backend mounts `~/.aws` read-only at
`/root/.aws`. The legacy Prowler/TruffleHog path still mounts the host Docker
socket to launch sibling containers; `HOST_DATA_DIR` must point at the same
`./data` directory on your host for that path.

### RhinoScan API

```
GET  /profiles              # scannable AWS profiles from ~/.aws/config
POST /scan                  # body: { "profiles": [...] } → { run_ids }
GET  /scan/{run_id}         # poll run status
GET  /findings              # ?profile= &severity= &category= &run_id=
GET  /findings/summary      # counts by severity + category, accounts scanned
GET  /report/{run_id}       # markdown baseline report
```

## V2 Roadmap

- PDF report generation (Gray Rhino branded)
- GitHub App OAuth (vs manual token)
- Additional TruffleHog detectors beyond AWS keys
- Executive narrative via Claude API
