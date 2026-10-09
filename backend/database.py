from sqlalchemy import create_engine, text, inspect
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from backend.config import settings


engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    import backend.models  # noqa: F401 — register all models with Base.metadata
    Base.metadata.create_all(bind=engine)
    _migrate_db()
    seed_admin()
    seed_provider_limits()


def _migrate_db():
    """Add columns that were added to models after initial table creation."""
    insp = inspect(engine)
    
    # proxies.provider_types (JSON, nullable)
    if "proxies" in insp.get_table_names():
        columns = [c["name"] for c in insp.get_columns("proxies")]
        if "provider_types" not in columns:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE proxies ADD COLUMN provider_types JSON"))
            print("Migration: added proxies.provider_types")

    # allowed_clients.provider_id (INTEGER, nullable, FK to providers.id)
    if "allowed_clients" in insp.get_table_names():
        columns = [c["name"] for c in insp.get_columns("allowed_clients")]
        if "provider_id" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE allowed_clients ADD COLUMN provider_id INTEGER REFERENCES providers(id) ON DELETE CASCADE"
                ))
                conn.execute(text(
                    "CREATE INDEX IF NOT EXISTS ix_allowed_clients_provider_id ON allowed_clients (provider_id)"
                ))
            print("Migration: added allowed_clients.provider_id")

        if "smtp_password_plain" not in columns:
            with engine.begin() as conn:
                conn.execute(text(
                    "ALTER TABLE allowed_clients ADD COLUMN smtp_password_plain VARCHAR(255)"
                ))
            print("Migration: added allowed_clients.smtp_password_plain")

    _migrate_hve_columns()
    _migrate_oauth_enum()


def _migrate_hve_columns():
    """Add High Volume Email OAuth columns to providers on existing databases."""
    insp = inspect(engine)
    if "providers" not in insp.get_table_names():
        return
    columns = {c["name"] for c in insp.get_columns("providers")}
    additions = {
        "oauth_tenant_id": "VARCHAR(64)",
        "oauth_client_id": "VARCHAR(64)",
        "oauth_credential": "VARCHAR(20)",
        "oauth_mode": "VARCHAR(20)",
        "oauth_status": "VARCHAR(32)",
        "oauth_client_secret_encrypted": "TEXT",
        "oauth_cert_pem_encrypted": "TEXT",
        "oauth_key_pem_encrypted": "TEXT",
        "oauth_refresh_token_encrypted": "TEXT",
        "oauth_access_token_encrypted": "TEXT",
        "oauth_token_expires_at": "TIMESTAMP",
        "oauth_device_code_encrypted": "TEXT",
        "oauth_device_expires_at": "TIMESTAMP",
        "oauth_poll_interval": "INTEGER",
        "oauth_pkce_verifier_encrypted": "TEXT",
        "oauth_user_code": "VARCHAR(64)",
        "oauth_verification_uri": "VARCHAR(512)",
    }
    missing = [name for name in additions if name not in columns]
    if not missing:
        return
    with engine.begin() as conn:
        for name in missing:
            conn.execute(text(f"ALTER TABLE providers ADD COLUMN {name} {additions[name]}"))
    print("Migration: added providers." + ", ".join(missing))


def _migrate_oauth_enum():
    """Allow auth_method 'oauth' on databases created before HVE existed."""
    if engine.dialect.name != "postgresql":
        return
    with engine.connect() as conn:
        rows = conn.execute(text("""
            SELECT t.typname, e.enumlabel
            FROM pg_enum e
            JOIN pg_type t ON e.enumtypid = t.oid
            WHERE e.enumlabel IN ('plain', 'PLAIN', 'app_password', 'APP_PASSWORD', 'api_key', 'API_KEY')
        """)).fetchall()
    if not rows:
        return
    by_type: dict[str, set[str]] = {}
    for typname, label in rows:
        by_type.setdefault(typname, set()).add(label)
    for typname, labels in by_type.items():
        if not typname.replace("_", "").isalnum():
            continue
        sample = next(iter(labels))
        new_label = "OAUTH" if sample.isupper() else "oauth"
        if new_label in labels:
            continue
        with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
            conn.execute(text(f"ALTER TYPE {typname} ADD VALUE IF NOT EXISTS '{new_label}'"))
        print(f"Migration: added enum {typname}.{new_label}")


def seed_admin():
    """Create default admin from .env if not exists."""
    from backend.config import settings
    from backend.models import User, UserRole
    from backend.services.auth import hash_password

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.admin_email).first()
        if not existing:
            admin = User(
                email=settings.admin_email,
                password_hash=hash_password(settings.admin_password),
                name="Admin",
                role=UserRole.ADMIN,
                is_active=True,
                is_verified=True,
                max_relays=100,
            )
            db.add(admin)
            db.commit()
            print(f"Admin account created: {settings.admin_email}")
        else:
            print(f"Admin account exists: {settings.admin_email}")
    finally:
        db.close()


def seed_provider_limits():
    """Seed provider_type_limits from presets (only inserts missing types)."""
    from backend.models import ProviderTypeLimit
    from backend.services.provider_presets import PROVIDER_PRESETS

    db = SessionLocal()
    try:
        for ptype, preset in PROVIDER_PRESETS.items():
            existing = db.query(ProviderTypeLimit).get(ptype)
            if not existing and preset.get("daily_limit") is not None:
                db.add(ProviderTypeLimit(
                    provider_type=ptype,
                    daily_limit=preset["daily_limit"],
                ))
        db.commit()
        print("Provider type limits seeded")
    finally:
        db.close()