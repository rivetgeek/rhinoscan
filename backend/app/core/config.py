from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "sqlite:////data/db/rhino.db"
    DATA_DIR: str = "/data"
    # Host path to DATA_DIR — required for Prowler/TruffleHog sibling containers
    HOST_DATA_DIR: str = ""

    GITHUB_APP_ID: str = ""
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_APP_PRIVATE_KEY_PATH: str = ""

    PROWLER_IMAGE: str = "toniblyx/prowler:latest"
    TRUFFLE_IMAGE: str = "trufflesecurity/trufflehog:latest"

    class Config:
        env_file = ".env"


settings = Settings()
