# Gray Rhino Security Scanner

Prowler + TruffleHog with AWS credential correlation. Clone and run locally with Docker.

## Prerequisites

- Docker + Docker Compose
- AWS credentials with permission to `sts:AssumeRole` into the target client role
- (Optional) GitHub token with org repo read access for TruffleHog

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

## IAM Role Requirements

The role you pass into the scanner needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "*" }
  ]
}
```

And the client's role needs these managed policies attached:
- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/IAMReadOnlyAccess`

The trust policy on the client role should trust your scanner's AWS identity (instance role or IAM user).

## V1 Local Test (AWS only)

1. Start the stack (above)
2. Open http://localhost:3000 → **New Scan**
3. Enter a client IAM role ARN and region
4. Leave GitHub fields blank to run Prowler only
5. Watch the job on the Scans page; open it when status is `complete`

For GitHub secret scanning, also provide org name and a token with repo read access.

## Data

Everything lives in `./data/` (gitignored except directory scaffolding):

- `./data/db/rhino.db` — SQLite database
- `./data/scans/<job-id>/` — raw Prowler + TruffleHog JSON
- `./data/reports/` — reserved for V2 PDF reports

## Architecture

```
React (port 3000) → nginx → FastAPI (port 8000) → SQLite
                                                 → Docker: Prowler container
                                                 → Docker: TruffleHog container
                                                 → boto3: IAM correlation
```

The backend mounts the host Docker socket to launch Prowler and TruffleHog as sibling containers. `HOST_DATA_DIR` must point to the same `./data` directory on your host so scan output is written correctly.

## V2 Roadmap

- PDF report generation (Gray Rhino branded)
- GitHub App OAuth (vs manual token)
- Additional TruffleHog detectors beyond AWS keys
- Executive narrative via Claude API
