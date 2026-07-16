from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:////data/db/rhino.db"
    DATA_DIR: str = "/data"
    # Host path to DATA_DIR — required for Prowler/TruffleHog sibling containers
    HOST_DATA_DIR: str = ""

    # Static bearer token required on /api/v1 when set. Empty disables auth —
    # acceptable only with ports bound to localhost (the compose default).
    RHINOSCAN_API_TOKEN: str = ""

    # ── AWS (RhinoScan native checks) ─────────────────────────────────────────
    # Path to the AWS config file boto3 reads profiles from. Defaults to the
    # standard ~/.aws/config; override to mount a client's config elsewhere.
    AWS_CONFIG_FILE: str = "~/.aws/config"
    # Profiles never surfaced for scanning (operator / default profiles).
    AWS_EXCLUDED_PROFILES: str = "default,grsconsultant"
    # Regional checks (GuardDuty, Security Hub, EC2, Lambda) default here.
    # Multi-region is a follow-on per the PRD.
    AWS_DEFAULT_REGION: str = "us-west-2"

    GITHUB_APP_ID: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_APP_PRIVATE_KEY_PATH: str = ""

    PROWLER_IMAGE: str = "toniblyx/prowler:latest"
    TRUFFLE_IMAGE: str = "trufflesecurity/trufflehog:latest"
    SCORECARD_IMAGE: str = "gcr.io/openssf/scorecard:stable"

    @property
    def excluded_profiles(self) -> set[str]:
        return {
            p.strip()
            for p in self.AWS_EXCLUDED_PROFILES.split(",")
            if p.strip()
        }

    class Config:
        env_file = ".env"


settings = Settings()
