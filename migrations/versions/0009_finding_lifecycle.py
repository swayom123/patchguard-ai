"""phase thirteen finding triage and suppression history"""

import sqlalchemy as sa
from alembic import op

revision = "0009_finding_lifecycle"
down_revision = "0008_patch_applications"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_triage_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("previous_status", sa.String(length=32), nullable=False),
        sa.Column("new_status", sa.String(length=32), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["security_findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_triage_events_finding_id", "finding_triage_events", ["finding_id"])

    op.create_table(
        "finding_suppressions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["finding_id"], ["security_findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_suppressions_finding_id", "finding_suppressions", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_finding_suppressions_finding_id", table_name="finding_suppressions")
    op.drop_table("finding_suppressions")
    op.drop_index("ix_finding_triage_events_finding_id", table_name="finding_triage_events")
    op.drop_table("finding_triage_events")
