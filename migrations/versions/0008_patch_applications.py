"""phase ten guarded worktree patch application"""

import sqlalchemy as sa
from alembic import op

revision = "0008_patch_applications"
down_revision = "0007_patch_workspaces"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_applications",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("patch_id", sa.String(length=36), nullable=False),
        sa.Column("worktree_path", sa.Text(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("backup_path", sa.Text(), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.Column("applied_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(["patch_id"], ["security_patches.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_patch_applications_patch_id", "patch_applications", ["patch_id"])


def downgrade() -> None:
    op.drop_index("ix_patch_applications_patch_id", table_name="patch_applications")
    op.drop_table("patch_applications")
