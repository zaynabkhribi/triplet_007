"""Persist incident lifecycle revisions."""

import sqlalchemy as sa

from alembic import op

revision = "0003_incident_revisions"
down_revision = "0002_forecasts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "incidents" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "incidents",
            sa.Column("id", sa.Uuid, primary_key=True),
            sa.Column("correlation_id", sa.Uuid, nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
            sa.Column("severity", sa.String(32), nullable=False),
        )
        for column in ("correlation_id", "occurred_at", "severity"):
            op.create_index(f"ix_incidents_{column}", "incidents", [column])
    if "incident_revisions" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "incident_revisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("incident_id", sa.Uuid, sa.ForeignKey("incidents.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    for column in ("incident_id", "created_at"):
        op.create_index(f"ix_incident_revisions_{column}", "incident_revisions", [column])


def downgrade() -> None:
    op.drop_table("incident_revisions")
