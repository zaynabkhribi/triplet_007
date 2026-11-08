"""Add registry and versioned city state without changing prior tables."""

import sqlalchemy as sa

from alembic import op

revision = "0001_city_state"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = sa.inspect(op.get_bind()).get_table_names()
    if "city_registry" not in existing:
        op.create_table(
            "city_registry",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("payload", sa.JSON, nullable=False),
        )
    if "city_snapshots" not in existing:
        op.create_table(
            "city_snapshots",
            sa.Column("version", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
        )
        op.create_index("ix_city_snapshots_created_at", "city_snapshots", ["created_at"])


def downgrade() -> None:
    op.drop_table("city_snapshots")
    op.drop_table("city_registry")
