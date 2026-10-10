"""phase nine isolated patch workspaces"""

import sqlalchemy as sa
from alembic import op

revision = "0007_patch_workspaces"
down_revision = "0006_patch_planning"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "patch_workspaces",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("patch_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("workspace_path", sa.Text(), nullable=False),
        sa.Column("source_hash", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["patch_id"], ["security_patches.id"]),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("patch_id", name="uq_patch_workspace_patch_id"),
        sa.UniqueConstraint("workspace_path"),
    )
    op.create_index("ix_patch_workspaces_patch_id", "patch_workspaces", ["patch_id"])
    op.create_index("ix_patch_workspaces_repository_id", "patch_workspaces", ["repository_id"])


def downgrade() -> None:
    op.drop_index("ix_patch_workspaces_repository_id", table_name="patch_workspaces")
    op.drop_index("ix_patch_workspaces_patch_id", table_name="patch_workspaces")
    op.drop_table("patch_workspaces")
