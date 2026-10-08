"""Phase 3 defensive SAST schema.

Revision ID: 0003
Revises: 0002
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("security_scans") as batch:
        batch.add_column(sa.Column("repository_index_id", sa.String(36)))
        batch.create_foreign_key(
            "fk_security_scans_repository_index",
            "repository_indexes",
            ["repository_index_id"],
            ["id"],
        )
        batch.create_index("ix_security_scans_repository_index_id", ["repository_index_id"])
    with op.batch_alter_table("scanner_runs") as batch:
        batch.add_column(
            sa.Column("execution_mode", sa.String(32), nullable=False, server_default="docker")
        )
        batch.add_column(sa.Column("execution_image", sa.String(300)))
        batch.add_column(sa.Column("duration_ms", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("exit_code", sa.Integer()))
        batch.add_column(
            sa.Column("output_truncated", sa.Boolean(), nullable=False, server_default=sa.false())
        )
        batch.create_index("ix_scanner_runs_scan_id", ["scan_id"])
    with op.batch_alter_table("security_findings") as batch:
        batch.add_column(
            sa.Column(
                "primary_rule_id",
                sa.String(200),
                nullable=False,
                server_default="legacy-unknown",
            )
        )
        batch.create_index("ix_security_findings_scan_id", ["scan_id"])
    with op.batch_alter_table("evidence") as batch:
        batch.add_column(sa.Column("scanner_run_id", sa.String(36)))
        batch.create_foreign_key(
            "fk_evidence_scanner_run", "scanner_runs", ["scanner_run_id"], ["id"]
        )
        batch.add_column(
            sa.Column("rule_id", sa.String(200), nullable=False, server_default="legacy-unknown")
        )
        batch.create_index("ix_evidence_finding_id", ["finding_id"])
        batch.create_index("ix_evidence_scanner_run_id", ["scanner_run_id"])


def downgrade() -> None:
    with op.batch_alter_table("evidence") as batch:
        batch.drop_index("ix_evidence_scanner_run_id")
        batch.drop_index("ix_evidence_finding_id")
        batch.drop_constraint("fk_evidence_scanner_run", type_="foreignkey")
        batch.drop_column("rule_id")
        batch.drop_column("scanner_run_id")
    with op.batch_alter_table("security_findings") as batch:
        batch.drop_index("ix_security_findings_scan_id")
        batch.drop_column("primary_rule_id")
    with op.batch_alter_table("scanner_runs") as batch:
        batch.drop_index("ix_scanner_runs_scan_id")
        batch.drop_column("output_truncated")
        batch.drop_column("exit_code")
        batch.drop_column("duration_ms")
        batch.drop_column("execution_image")
        batch.drop_column("execution_mode")
    with op.batch_alter_table("security_scans") as batch:
        batch.drop_index("ix_security_scans_repository_index_id")
        batch.drop_constraint("fk_security_scans_repository_index", type_="foreignkey")
        batch.drop_column("repository_index_id")
