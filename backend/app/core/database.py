import json

from sqlalchemy import MetaData, create_engine, inspect, text
from sqlalchemy.schema import CreateTable
from sqlalchemy.orm import sessionmaker
from app.models.db import Base, Run
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


# Maps a legacy scan_jobs status column to the engine name it tracked.
_LEGACY_ENGINE_COLS = {
    "prowler_status": "prowler-aws",
    "prowler_github_status": "prowler-github",
    "truffle_status": "trufflehog",
    "scorecard_status": "scorecard",
}


def _migrate():
    """Apply lightweight schema fixes for already-created tables.

    create_all never alters existing tables, so this converges v1 databases
    onto the unified run model:
      - runs gains target/engines/engine_status/errors (was profile-only)
      - legacy scan_jobs rows become runs rows; scan_jobs is dropped
      - engine detail tables rename job_id -> run_id
      - additive columns from earlier revisions (findings.origin/api,
        prowler_findings.provider) for pre-v1.1 databases
    """
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())

    if "runs" in tables:
        run_cols = {c["name"] for c in inspector.get_columns("runs")}
        if "target" not in run_cols:
            _rebuild_runs()
            inspector = inspect(engine)
            tables = set(inspector.get_table_names())

    if "scan_jobs" in tables:
        _migrate_scan_jobs_to_runs()
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())

    for table in ("prowler_findings", "truffle_findings",
                  "correlated_alerts", "scorecard_findings"):
        if table not in tables:
            continue
        columns = {c["name"] for c in inspector.get_columns(table)}
        if "job_id" in columns and "run_id" not in columns:
            with engine.begin() as conn:
                conn.exec_driver_sql(
                    f"ALTER TABLE {table} RENAME COLUMN job_id TO run_id"
                )

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


def _rebuild_runs():
    """Recreate runs from the current model, preserving v1 baseline rows.

    Standard SQLite table-rebuild (SQLite can't add NOT NULL columns to a
    populated table without defaults): create under a temp name, copy rows
    mapping profile -> target and synthesizing the engine columns (v1 runs
    were always the baseline engine), drop, rename into place.
    """
    tmp = Run.__table__.to_metadata(MetaData(), name="runs_new")
    create_sql = str(CreateTable(tmp).compile(engine))

    engines_json = json.dumps(["baseline"])
    with engine.begin() as conn:
        conn.exec_driver_sql(create_sql)
        rows = conn.exec_driver_sql(
            "SELECT id, profile, started_at, completed_at, finding_count, status FROM runs"
        ).fetchall()
        for r in rows:
            status = r[5] or "failed"
            # A run can't still be running across a restart.
            if status == "running":
                status = "failed"
            conn.exec_driver_sql(
                "INSERT INTO runs_new (id, target, engines, engine_status, errors, "
                "started_at, completed_at, finding_count, status) "
                "VALUES (?, ?, ?, ?, NULL, ?, ?, ?, ?)",
                (r[0], r[1], engines_json,
                 json.dumps({"baseline": status}),
                 r[2], r[3], r[4], status),
            )
        conn.exec_driver_sql("DROP TABLE runs")
        conn.exec_driver_sql("ALTER TABLE runs_new RENAME TO runs")


def _migrate_scan_jobs_to_runs():
    """Fold legacy scan_jobs rows into runs (same ids, so the engine detail
    tables' run_id references stay valid), then drop scan_jobs."""
    inspector = inspect(engine)
    columns = {c["name"] for c in inspector.get_columns("scan_jobs")}

    with engine.begin() as conn:
        jobs = conn.exec_driver_sql("SELECT * FROM scan_jobs").mappings().all()
        existing = {
            r[0] for r in conn.exec_driver_sql("SELECT id FROM runs").fetchall()
        }
        for j in jobs:
            if j["id"] in existing:
                continue

            def col(name):
                return j[name] if name in columns else None

            target = (
                col("profile")
                or (f"github:{col('github_org')}" if col("github_org") else None)
                or col("role_arn")
                or "unknown"
            )
            engine_status = {}
            for status_col, engine_name in _LEGACY_ENGINE_COLS.items():
                status = col(status_col)
                if status is None:
                    continue
                if status in ("running", "pending"):
                    status = "failed"  # stale — the process is long gone
                engine_status[engine_name] = status
            engines_list = [e for e, s in engine_status.items() if s != "skipped"]

            status = j["status"] or "failed"
            if status in ("running", "pending"):
                status = "failed"

            errors = None
            if col("error_message"):
                errors = json.dumps({"legacy": col("error_message")})

            conn.exec_driver_sql(
                "INSERT INTO runs (id, target, engines, engine_status, errors, "
                "started_at, completed_at, finding_count, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                (j["id"], target, json.dumps(engines_list),
                 json.dumps(engine_status), errors,
                 str(col("created_at") or ""), str(col("updated_at") or "") or None,
                 status),
            )
        conn.exec_driver_sql("DROP TABLE scan_jobs")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
