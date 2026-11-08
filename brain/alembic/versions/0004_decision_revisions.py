"""Persist decision lifecycle revisions."""

import sqlalchemy as sa

from alembic import op

revision = "0004_decision_revisions"
down_revision = "0003_incident_revisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "decisions" not in sa.inspect(op.get_bind()).get_table_names():
        op.create_table(
            "decisions",
            sa.Column("id", sa.Uuid, primary_key=True),
            sa.Column("correlation_id", sa.Uuid, nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
        )
        for column in ("correlation_id", "occurred_at", "status"):
            op.create_index(f"ix_decisions_{column}", "decisions", [column])
    if "decision_revisions" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "decision_revisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("decision_id", sa.Uuid, sa.ForeignKey("decisions.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    for column in ("decision_id", "created_at"):
        op.create_index(f"ix_decision_revisions_{column}", "decision_revisions", [column])


def downgrade() -> None:
    op.drop_table("decision_revisions")
