"""EC2 / Network baseline checks (region-scoped to the default region)."""

from .base import HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "EC2"


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    ec2 = ctx.client("ec2")

    out += _security_groups(ctx, ec2)
    out += _instances_imdsv2(ctx, ec2)
    out += _unencrypted_volumes(ctx, ec2)
    out += _unencrypted_snapshots(ctx, ec2)
    out += _default_vpc(ctx, ec2)
    return out


def _security_groups(ctx, ec2) -> list[Finding]:
    out: list[Finding] = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            arn = f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:security-group/{sg_id}"
            for perm in sg.get("IpPermissions", []):
                port = _port_desc(perm)
                if any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])):
                    out.append(finding(
                        ctx, category=CATEGORY, severity=HIGH,
                        title=f"Security group {sg_id} allows 0.0.0.0/0 ingress on {port}",
                        resource=arn,
                        description=f"Security group '{sg.get('GroupName')}' permits inbound "
                                    f"traffic from any IPv4 address on {port}.",
                        remediation="Restrict ingress to known CIDR ranges or use SSM/VPN.",
                        source="ec2_sg_open_ipv4", raw=perm,
                    ))
                if any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", [])):
                    out.append(finding(
                        ctx, category=CATEGORY, severity=HIGH,
                        title=f"Security group {sg_id} allows ::/0 ingress on {port}",
                        resource=arn,
                        description=f"Security group '{sg.get('GroupName')}' permits inbound "
                                    f"traffic from any IPv6 address on {port}.",
                        remediation="Restrict IPv6 ingress to known ranges.",
                        source="ec2_sg_open_ipv6", raw=perm,
                    ))
    return out


def _port_desc(perm) -> str:
    if perm.get("IpProtocol") == "-1":
        return "all ports"
    f, t = perm.get("FromPort"), perm.get("ToPort")
    if f is None:
        return "unspecified ports"
    return f"port {f}" if f == t else f"ports {f}-{t}"


def _instances_imdsv2(ctx, ec2) -> list[Finding]:
    out: list[Finding] = []
    paginator = ec2.get_paginator("describe_instances")
    for page in paginator.paginate():
        for res in page.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst.get("State", {}).get("Name") in ("terminated", "shutting-down"):
                    continue
                meta = inst.get("MetadataOptions", {})
                if meta.get("HttpTokens") != "required":
                    iid = inst["InstanceId"]
                    out.append(finding(
                        ctx, category=CATEGORY, severity=MEDIUM,
                        title=f"Instance {iid} does not enforce IMDSv2",
                        resource=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:instance/{iid}",
                        description="The instance metadata service allows IMDSv1, which is "
                                    "vulnerable to SSRF credential theft.",
                        remediation="Set HttpTokens=required to enforce IMDSv2.",
                        source="ec2_imdsv2", raw=meta,
                    ))
    return out


def _unencrypted_volumes(ctx, ec2) -> list[Finding]:
    out: list[Finding] = []
    paginator = ec2.get_paginator("describe_volumes")
    for page in paginator.paginate():
        for vol in page.get("Volumes", []):
            if not vol.get("Encrypted"):
                vid = vol["VolumeId"]
                out.append(finding(
                    ctx, category=CATEGORY, severity=MEDIUM,
                    title=f"EBS volume {vid} is not encrypted",
                    resource=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:volume/{vid}",
                    description="The EBS volume is not encrypted at rest.",
                    remediation="Encrypt EBS volumes; enable account-level default EBS encryption.",
                    source="ec2_unencrypted_volume", raw=vol,
                ))
    return out


def _unencrypted_snapshots(ctx, ec2) -> list[Finding]:
    out: list[Finding] = []
    paginator = ec2.get_paginator("describe_snapshots")
    for page in paginator.paginate(OwnerIds=["self"]):
        for snap in page.get("Snapshots", []):
            if not snap.get("Encrypted"):
                sid = snap["SnapshotId"]
                out.append(finding(
                    ctx, category=CATEGORY, severity=LOW,
                    title=f"EBS snapshot {sid} is not encrypted",
                    resource=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:snapshot/{sid}",
                    description="The EBS snapshot is not encrypted at rest.",
                    remediation="Copy the snapshot with encryption enabled and delete the unencrypted copy.",
                    source="ec2_unencrypted_snapshot", raw=snap,
                ))
    return out


def _default_vpc(ctx, ec2) -> list[Finding]:
    vpcs = ec2.describe_vpcs(
        Filters=[{"Name": "isDefault", "Values": ["true"]}]
    ).get("Vpcs", [])
    out: list[Finding] = []
    for vpc in vpcs:
        vid = vpc["VpcId"]
        out.append(finding(
            ctx, category=CATEGORY, severity=LOW,
            title=f"Default VPC {vid} exists in {ctx.region}",
            resource=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:vpc/{vid}",
            description="A default VPC exists. Default VPCs ship with permissive networking "
                        "and are often unused.",
            remediation="Delete unused default VPCs to reduce attack surface.",
            source="ec2_default_vpc", raw=vpc,
        ))
    return out
