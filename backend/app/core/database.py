from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.schema import CreateTable
from sqlalchemy.orm import sessionmaker
from app.models.db import Base, ScanJob
from app.core.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False},  # SQLite only
    echo=False,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate()


def _migrate():
    """Apply lightweight, additive schema fixes for already-created tables.

    create_all never alters existing tables, so add columns introduced after a
    table first shipped:
      - scan_jobs.profile (legacy path moved from a pasted role ARN to a profile)
      - scan_jobs.prowler_github_status / scan_jobs.scorecard_status
        (Prowler GitHub provider + OpenSSF Scorecard scanners)
      - prowler_findings.provider (distinguishes AWS vs GitHub Prowler rows)
      - findings.origin / findings.api (finding provenance + the AWS API call
        backing it, for manual verification)
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    if "scan_jobs" in tables:
        # role_arn is legacy (superseded by profile) and no longer populated, but
        # early DBs created it NOT NULL — which blocks every new scan insert.
        # SQLite can't drop a NOT NULL via ALTER, so rebuild the table from the
        # current model (preserving rows) when the old constraint is still there.
        role_arn = next(
            (c for c in inspector.get_columns("scan_jobs") if c["name"] == "role_arn"),
            None,
        )
        if role_arn is not None and role_arn["nullable"] is False:
            _rebuild_scan_jobs()
            inspector = inspect(engine)  # refresh after the rebuild

        columns = {c["name"] for c in inspector.get_columns("scan_jobs")}
        with engine.begin() as conn:
            if "profile" not in columns:
                conn.execute(text("ALTER TABLE scan_jobs ADD COLUMN profile VARCHAR"))
            if "prowler_github_status" not in columns:
                conn.execute(text(
                    "ALTER TABLE scan_jobs ADD COLUMN prowler_github_status VARCHAR DEFAULT 'pending'"
                ))
            if "scorecard_status" not in columns:
                conn.execute(text(
                    "ALTER TABLE scan_jobs ADD COLUMN scorecard_status VARCHAR DEFAULT 'pending'"
                ))

    if "prowler_findings" in tables:
        columns = {c["name"] for c in inspector.get_columns("prowler_findings")}
        if "provider" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE prowler_findings ADD COLUMN provider VARCHAR DEFAULT 'aws'"
                ))

    if "findings" in tables:
        columns = {c["name"] for c in inspector.get_columns("findings")}
        with engine.begin() as conn:
            if "origin" not in columns:
                conn.execute(text(
                    "ALTER TABLE findings ADD COLUMN origin VARCHAR DEFAULT 'Baseline'"
                ))
            if "api" not in columns:
                conn.execute(text("ALTER TABLE findings ADD COLUMN api VARCHAR"))


def _rebuild_scan_jobs():
    """Recreate scan_jobs from the current model, preserving existing rows.

    Standard SQLite table-rebuild: create the new table under a temp name, copy
    the columns common to both, drop the old table, rename into place. FK
    enforcement is off by default on SQLAlchemy's SQLite connections, so the
    drop/rename is safe and child references resolve again once renamed.
    """
    old_cols = {c["name"] for c in inspect(engine).get_columns("scan_jobs")}
    model_cols = [c.name for c in ScanJob.__table__.columns]
    common = [c for c in model_cols if c in old_cols]
    collist = ", ".join(common)

    tmp = ScanJob.__table__.to_metadata(MetaData(), name="scan_jobs_new")
    create_sql = str(CreateTable(tmp).compile(engine))

    with engine.begin() as conn:
        conn.exec_driver_sql(create_sql)
        conn.exec_driver_sql(
            f"INSERT INTO scan_jobs_new ({collist}) SELECT {collist} FROM scan_jobs"
        )
        conn.exec_driver_sql("DROP TABLE scan_jobs")
        conn.exec_driver_sql("ALTER TABLE scan_jobs_new RENAME TO scan_jobs")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
