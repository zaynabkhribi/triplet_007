"""Persist dashboard scenario executions and timeline logs."""

import sqlalchemy as sa

from alembic import op

revision = "0006_scenario_logs"
down_revision = "0005_command_revisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = sa.inspect(op.get_bind()).get_table_names()
    if "scenario_executions" not in existing:
        op.create_table(
            "scenario_executions",
            sa.Column("id", sa.Uuid, primary_key=True),
            sa.Column("correlation_id", sa.Uuid, nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
            sa.Column("scenario_id", sa.String(64), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
        )
        for column in ("correlation_id", "occurred_at", "scenario_id", "status"):
            op.create_index(f"ix_scenario_executions_{column}", "scenario_executions", [column])
    if "scenario_logs" in existing:
        return
    op.create_table(
        "scenario_logs",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("execution_id", sa.Uuid, sa.ForeignKey("scenario_executions.id"), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stage", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("detail", sa.JSON, nullable=False),
    )
    for column in ("execution_id", "occurred_at", "stage", "status"):
        op.create_index(f"ix_scenario_logs_{column}", "scenario_logs", [column])


def downgrade() -> None:
    op.drop_table("scenario_logs")
    op.drop_table("scenario_executions")
