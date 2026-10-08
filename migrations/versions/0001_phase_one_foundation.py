"""Phase 1 foundation schema.

Revision ID: 0001
Revises:
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("path", sa.Text(), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("default_branch", sa.String(255)),
        sa.Column("commit_hash", sa.String(64)),
        sa.Column("profile", sa.JSON(), nullable=False),
        sa.Column("read_only", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "security_scans",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("trace_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("mode", sa.String(16), nullable=False),
        sa.Column("repository_commit", sa.String(64)),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "scanner_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("security_scans.id"), nullable=False),
        sa.Column("scanner_name", sa.String(100), nullable=False),
        sa.Column("scanner_version", sa.String(100)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("findings_count", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "security_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("scan_id", sa.String(36), sa.ForeignKey("security_scans.id"), nullable=False),
        sa.Column("fingerprint", sa.String(128), nullable=False),
        sa.Column("scanner", sa.String(100), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("cwe_id", sa.String(20)),
        sa.Column("cwe_name", sa.String(255)),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_start", sa.Integer()),
        sa.Column("line_end", sa.Integer()),
        sa.Column("code_reference", sa.String(500)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("scan_id", "fingerprint", name="uq_finding_scan_fingerprint"),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "finding_id", sa.String(36), sa.ForeignKey("security_findings.id"), nullable=False
        ),
        sa.Column("scanner", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(100), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("source_reference", sa.Text()),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "security_patches",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "finding_id", sa.String(36), sa.ForeignKey("security_findings.id"), nullable=False
        ),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("operation", sa.String(32), nullable=False),
        sa.Column("original_hash", sa.String(128), nullable=False),
        sa.Column("diff", sa.Text(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "verification_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("patch_id", sa.String(36), sa.ForeignKey("security_patches.id"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("sandbox_kind", sa.String(50), nullable=False),
        sa.Column("network_enabled", sa.Boolean(), nullable=False),
        sa.Column("checks", sa.JSON(), nullable=False),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )


def downgrade() -> None:
    op.drop_table("verification_runs")
    op.drop_table("security_patches")
    op.drop_table("evidence")
    op.drop_table("security_findings")
    op.drop_table("scanner_runs")
    op.drop_table("security_scans")
    op.drop_table("repositories")
