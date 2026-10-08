"""phase five evidence-bound assessments"""

import sqlalchemy as sa
from alembic import op

revision = "0005_ai_analysis"
down_revision = "0004_phase_four_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("finding_id", sa.String(length=36), nullable=False),
        sa.Column("provider", sa.String(length=100), nullable=False),
        sa.Column("model_name", sa.String(length=255)),
        sa.Column("classification", sa.String(length=32), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.Column("evidence_strength", sa.String(length=16), nullable=False),
        sa.Column("root_cause", sa.Text(), nullable=False),
        sa.Column("reasoning_summary", sa.Text(), nullable=False),
        sa.Column("affected_components", sa.JSON(), nullable=False),
        sa.Column("recommended_fix", sa.Text(), nullable=False),
        sa.Column("context_digest", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["finding_id"], ["security_findings.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_assessments_finding_id", "security_assessments", ["finding_id"])


def downgrade() -> None:
    op.drop_index("ix_security_assessments_finding_id", table_name="security_assessments")
    op.drop_table("security_assessments")
