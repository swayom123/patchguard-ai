"""phase six review-only patch plans"""

import sqlalchemy as sa
from alembic import op

revision = "0006_patch_planning"
down_revision = "0005_ai_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_patch_plans",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("files_to_modify", sa.JSON(), nullable=False),
        sa.Column("strategy", sa.Text(), nullable=False),
        sa.Column("behavioral_change", sa.Text(), nullable=False),
        sa.Column("compatibility_risks", sa.JSON(), nullable=False),
        sa.Column("tests_required", sa.JSON(), nullable=False),
        sa.Column("rollback_plan", sa.Text(), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["security_findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_patch_plans_finding_id", "security_patch_plans", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_security_patch_plans_finding_id", table_name="security_patch_plans")
    op.drop_table("security_patch_plans")
