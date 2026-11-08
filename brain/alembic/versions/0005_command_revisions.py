"""Persist actuator command lifecycle revisions."""

import sqlalchemy as sa

from alembic import op

revision = "0005_command_revisions"
down_revision = "0004_decision_revisions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = sa.inspect(op.get_bind()).get_table_names()
    if "actuator_commands" not in existing:
        op.create_table(
            "actuator_commands",
            sa.Column("id", sa.Uuid, primary_key=True),
            sa.Column("correlation_id", sa.Uuid, nullable=False),
            sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("payload", sa.JSON, nullable=False),
            sa.Column("actuator_id", sa.String(128), nullable=False),
            sa.Column("status", sa.String(32), nullable=False),
        )
        for column in ("correlation_id", "occurred_at", "actuator_id", "status"):
            op.create_index(f"ix_actuator_commands_{column}", "actuator_commands", [column])
    if "command_revisions" in existing:
        return
    op.create_table(
        "command_revisions",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("command_id", sa.Uuid, sa.ForeignKey("actuator_commands.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", sa.JSON, nullable=False),
    )
    for column in ("command_id", "created_at"):
        op.create_index(f"ix_command_revisions_{column}", "command_revisions", [column])


def downgrade() -> None:
    op.drop_table("command_revisions")
