"""phase four dependency inventory"""

import sqlalchemy as sa
from alembic import op

revision = "0004_phase_four_security"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "dependency_records",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("repository_id", sa.String(length=36), nullable=False),
        sa.Column("package", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=255)),
        sa.Column("manifest_path", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
        sa.Column("dependency_group", sa.String(length=255)),
        sa.Column("pinned", sa.Boolean(), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["repository_id"], ["repositories.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["security_scans.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id",
            "manifest_path",
            "package",
            "dependency_group",
            name="uq_dependency_observation",
        ),
    )
    op.create_index("ix_dependency_records_scan_id", "dependency_records", ["scan_id"])
    op.create_index("ix_dependency_records_repository_id", "dependency_records", ["repository_id"])


def downgrade() -> None:
    op.drop_index("ix_dependency_records_repository_id", table_name="dependency_records")
    op.drop_index("ix_dependency_records_scan_id", table_name="dependency_records")
    op.drop_table("dependency_records")
