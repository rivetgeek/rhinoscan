---
id: rhinoscan-001
title: RhinoScan — AWS Baseline Security Assessment Platform
status: draft
priority: high
created: 2026-06-25
author: remington.winters
product: rhinoscan
---

# RhinoScan — AWS Baseline Security Assessment Platform

## Overview

RhinoScan is a standalone Gray Rhino Security assessment platform. It runs a battery of nondestructive read-only AWS security checks against configured client profiles, surfaces findings in a unified dashboard, persists results in SQLite for delta tracking, and generates markdown reports. It is distinct from Hephaestus, which handles intelligence and agent orchestration. RhinoScan is the client-facing assessment tool.

## Architecture

- **Backend:** FastAPI
- **Frontend:** React
- **Database:** SQLite (separate from Hephaestus)
- **AWS Auth:** boto3 reading `~/.aws/config` profile chain
- **Repo:** separate from Hephaestus

## Goals

- Run a predefined battery of nondestructive read-only AWS checks against any configured client profile
- Display findings in a unified dashboard with per-source filtering
- Store results in SQLite for delta tracking across runs
- Generate a markdown baseline report on demand
- Lay the groundwork for Prowler, TruffleHog, and Semgrep integration

## Non-Goals

- No remediation actions — read only, no writes to client environment
- No real-time continuous scanning in this version — on-demand only
- No Hephaestus integration in this version
- No cross-account aggregation in this version — per-profile results only

---

## Profile Source Selector

### Backend

```
GET /profiles
```

Returns all profiles from `~/.aws/config` excluding `default` and `grsconsultant`.

```json
{
  "profiles": [
    "crexi-main",
    "crexi-prime",
    "crexi-shared",
    "crexi-devacct",
    "crexi-sandbox",
    "crexi-external",
    "crexi-groundcover",
    "crexi-data-dev",
    "crexi-data-stg",
    "crexi-data-prod"
  ]
}
```

### Frontend

Source selector in dashboard header. Options:

- **All** — aggregate view across all profiles
- Individual profile — filter to single account

Selector populates dynamically from `/profiles` endpoint on load.

---

## Baseline Check Battery

All checks use `boto3.Session(profile_name=profile)`. All checks are read-only. All checks return one or more Finding objects.

### Identity

| Check | Service | Method |
|-------|---------|--------|
| Credential report — key age, last used, MFA status | IAM | `generate_credential_report` / `get_credential_report` |
| Root account MFA status | IAM | `get_account_summary` |
| Root account active access keys | IAM | credential report |
| Users with keys older than 90 days | IAM | credential report |
| Users with two active access keys | IAM | credential report |
| Users with console access and no MFA | IAM | credential report |
| Password policy | IAM | `get_account_password_policy` |
| Human IAM users (email format username) | IAM | `list_users` |

### S3

| Check | Service | Method |
|-------|---------|--------|
| Account-level Block Public Access | S3Control | `get_public_access_block` |
| Buckets with public ACLs | S3 | `get_bucket_acl` per bucket |
| Buckets with public bucket policies | S3 | `get_bucket_policy_status` per bucket |
| Buckets without versioning | S3 | `get_bucket_versioning` per bucket |
| Buckets without encryption | S3 | `get_bucket_encryption` per bucket |
| Buckets without logging | S3 | `get_bucket_logging` per bucket |

### CloudTrail

| Check | Service | Method |
|-------|---------|--------|
| Trails configured | CloudTrail | `describe_trails` |
| Multi-region trail exists | CloudTrail | `describe_trails` |
| Log file validation enabled | CloudTrail | `describe_trails` |
| CloudWatch Logs integration | CloudTrail | `describe_trails` |
| Trail logging status | CloudTrail | `get_trail_status` per trail |

### GuardDuty

| Check | Service | Method |
|-------|---------|--------|
| Detector status per region | GuardDuty | `list_detectors` |
| All findings grouped by severity | GuardDuty | `list_findings` / `get_findings` |
| High severity findings (>= 7.0) | GuardDuty | `list_findings` with severity filter |
| Finding type summary | GuardDuty | aggregate from findings |

### Security Hub

| Check | Service | Method |
|-------|---------|--------|
| Security Hub enabled per region | SecurityHub | `describe_hub` |
| Active standards | SecurityHub | `get_enabled_standards` |
| Failed controls summary | SecurityHub | `get_findings` |

### EC2 / Network

| Check | Service | Method |
|-------|---------|--------|
| Security groups with 0.0.0.0/0 ingress | EC2 | `describe_security_groups` |
| Security groups with ::/0 ingress | EC2 | `describe_security_groups` |
| Instances without IMDSv2 enforced | EC2 | `describe_instances` |
| Unencrypted EBS volumes | EC2 | `describe_volumes` |
| Unencrypted snapshots | EC2 | `describe_snapshots` |
| Default VPC exists | EC2 | `describe_vpcs` |

### Lambda

| Check | Service | Method |
|-------|---------|--------|
| Functions with environment variables | Lambda | `list_functions` / `get_function_configuration` |
| Functions with public URLs | Lambda | `list_function_url_configs` |
| Functions using deprecated runtimes | Lambda | `list_functions` |
| Function execution role summary | Lambda | `list_functions` |

### Account

| Check | Service | Method |
|-------|---------|--------|
| Alternate contacts configured | Account | `get_alternate_contact` |
| Config recorder status | Config | `describe_configuration_recorders` |
| Config delivery channel | Config | `describe_delivery_channels` |
| IAM Access Analyzer active | AccessAnalyzer | `list_analyzers` |
| Account-level EBS encryption default | EC2 | `get_ebs_encryption_by_default` |

---

## Finding Data Model

```python
@dataclass
class Finding:
    id: str                  # deterministic hash of profile + source + resource
    profile: str             # aws profile name e.g. crexi-main
    account_id: str          # aws account id
    timestamp: str           # iso8601
    category: str            # Identity | S3 | CloudTrail | GuardDuty | EC2 | Lambda | Account
    severity: str            # Critical | High | Medium | Low | Informational
    title: str               # short description
    resource: str            # arn or resource identifier
    description: str         # full finding detail
    remediation: str         # recommended fix
    source: str              # check name e.g. s3_account_block_public_access
    raw: dict                # raw boto3 response
```

---

## SQLite Schema

```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    account_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    resource TEXT NOT NULL,
    description TEXT NOT NULL,
    remediation TEXT NOT NULL,
    source TEXT NOT NULL,
    raw TEXT,
    run_id TEXT NOT NULL
);

CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    profile TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    finding_count INTEGER,
    status TEXT
);
```

---

## API Endpoints

```
GET  /profiles                    # list available aws profiles
POST /scan                        # trigger baseline scan
     body: { profiles: [...] }    # one or more profiles
GET  /scan/{run_id}               # poll scan status
GET  /findings                    # query findings
     ?profile=crexi-main          # filter by profile
     ?severity=High               # filter by severity
     ?category=S3                 # filter by category
     ?run_id=...                  # filter by run
GET  /findings/summary            # aggregate counts by severity and category
GET  /report/{run_id}             # generate markdown report for run
```

---

## Dashboard

### Source Selector
Dropdown in header. Options: All + each profile from `/profiles`. Filters entire dashboard on change.

### Summary Cards
- Critical findings count
- High findings count
- Medium findings count
- Accounts scanned
- Last scan timestamp

### Findings Table
Columns: Severity | Category | Title | Resource | Profile | Timestamp

Sortable by severity. Filterable by category. Expandable row shows description and remediation.

### Category Breakdown
Bar or donut chart — finding count by category. Clicking category filters findings table.

### Severity Trend (future)
Line chart showing finding counts across runs once multiple runs exist.

---

## Report Output

```markdown
# RhinoScan Baseline Security Assessment
**Client:** {client name}
**Account:** {profile} ({account_id})
**Date:** {date}
**Run ID:** {run_id}

## Executive Summary
X critical, Y high, Z medium findings across N checks.

## Critical Findings
...

## High Findings
...

## Remediation Priority List
Ordered by severity and ease of fix.

---
*Generated by RhinoScan — Gray Rhino Security*
```

---

## Implementation Notes

- Boto3 sessions created per profile — credential chaining handled automatically via `~/.aws/config`
- Regional checks (GuardDuty, Security Hub, EC2, Lambda) default to `us-west-2` — multi-region support is a follow-on
- Scan runs async — POST /scan returns run_id immediately, frontend polls /scan/{run_id} for status
- Errors per check caught and logged as Informational findings — a failed check never crashes the full scan
- Finding IDs are deterministic hashes of profile + source + resource — re-runs produce stable IDs, delta is trackable
- No data leaves the local machine — all boto3 calls go directly to AWS via assumed role credentials

## Future Integrations

- Prowler — replace or supplement native checks with Prowler output parsed into Finding dataclass
- TruffleHog — secrets scanning against client GitHub org, findings into same schema
- Semgrep — static analysis against client codebase, findings into same schema
- Multi-region support — loop all enabled regions per check
- Multi-account aggregate view — roll up findings across all profiles for a client
