"""Lambda baseline checks (region-scoped to the default region)."""

from collections import Counter

from botocore.exceptions import ClientError

from .base import HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "Lambda"

# Runtimes EOL'd or deprecated by AWS — flagged as Medium.
DEPRECATED_RUNTIMES = {
    "python2.7", "python3.6", "python3.7",
    "nodejs", "nodejs4.3", "nodejs6.10", "nodejs8.10",
    "nodejs10.x", "nodejs12.x", "nodejs14.x",
    "ruby2.5", "ruby2.7", "dotnetcore1.0", "dotnetcore2.0",
    "dotnetcore2.1", "dotnetcore3.1", "go1.x", "java8",
}

# Env var names that strongly suggest a plaintext secret.
SECRET_HINTS = ("SECRET", "PASSWORD", "TOKEN", "APIKEY", "API_KEY", "PRIVATE_KEY", "ACCESS_KEY")


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    lam = ctx.client("lambda")

    functions = []
    paginator = lam.get_paginator("list_functions")
    for page in paginator.paginate():
        functions.extend(page.get("Functions", []))

    runtime_counts = Counter()
    role_counts = Counter()

    for fn in functions:
        name = fn["FunctionName"]
        arn = fn.get("FunctionArn", name)
        runtime = fn.get("Runtime", "")
        runtime_counts[runtime] += 1
        role_counts[fn.get("Role", "")] += 1

        # Env vars with secret-like names.
        env = fn.get("Environment", {}).get("Variables", {}) or {}
        suspicious = [k for k in env if any(h in k.upper() for h in SECRET_HINTS)]
        if suspicious:
            out.append(finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title=f"Function '{name}' has secret-like environment variables",
                resource=arn,
                description="Environment variables that look like secrets were found: "
                            + ", ".join(suspicious) + ". Plaintext env vars are visible to "
                            "anyone with lambda:GetFunctionConfiguration.",
                remediation="Move secrets to AWS Secrets Manager or SSM Parameter Store (SecureString).",
                source="lambda_env_secrets", raw={"keys": suspicious},
            ))

        # Deprecated runtime.
        if runtime in DEPRECATED_RUNTIMES:
            out.append(finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title=f"Function '{name}' uses deprecated runtime {runtime}",
                resource=arn,
                description=f"The function runs on {runtime}, which AWS has deprecated and no "
                            "longer patches.",
                remediation="Migrate the function to a supported runtime.",
                source="lambda_deprecated_runtime", raw={"runtime": runtime},
            ))

        # Public function URL.
        try:
            urls = lam.list_function_url_configs(FunctionName=name).get("FunctionUrlConfigs", [])
            for u in urls:
                if u.get("AuthType") == "NONE":
                    out.append(finding(
                        ctx, category=CATEGORY, severity=HIGH,
                        title=f"Function '{name}' has a public (unauthenticated) function URL",
                        resource=u.get("FunctionUrl", arn),
                        description="The function URL uses AuthType NONE, exposing it to the internet "
                                    "without authentication.",
                        remediation="Set AuthType to AWS_IAM or place the URL behind an authenticated gateway.",
                        source="lambda_public_url", raw=u,
                    ))
        except ClientError:
            pass

    if functions:
        out.append(finding(
            ctx, category=CATEGORY, severity=LOW,
            title=f"{len(functions)} Lambda function(s) across {len(role_counts)} execution role(s)",
            resource=f"arn:aws:lambda:{ctx.region}:{ctx.account_id}:function/*",
            description=f"Execution role distribution summary. Runtimes in use: {dict(runtime_counts)}.",
            remediation="Review execution roles for least privilege; consolidate where appropriate.",
            source="lambda_role_summary",
            raw={"runtime_counts": dict(runtime_counts), "role_count": len(role_counts)},
        ))

    return out
