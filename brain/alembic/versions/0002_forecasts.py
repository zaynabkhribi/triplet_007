"""Persist forecast requests and inference status."""

import sqlalchemy as sa

from alembic import op

revision = "0002_forecasts"
down_revision = "0001_city_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "forecasts" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "forecasts",
        sa.Column("id", sa.Uuid, primary_key=True),
        sa.Column("correlation_id", sa.Uuid, nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("family", sa.String(32), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )
    for column in ("correlation_id", "occurred_at", "family", "status"):
        op.create_index(f"ix_forecasts_{column}", "forecasts", [column])


def downgrade() -> None:
    op.drop_table("forecasts")
