"""Phase 2 repository intelligence schema.

Revision ID: 0002
Revises: 0001
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "repository_indexes",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("repository_id", sa.String(36), sa.ForeignKey("repositories.id"), nullable=False),
        sa.Column("repository_commit", sa.String(64)),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("file_count", sa.Integer(), nullable=False),
        sa.Column("symbol_count", sa.Integer(), nullable=False),
        sa.Column("import_count", sa.Integer(), nullable=False),
        sa.Column("call_count", sa.Integer(), nullable=False),
        sa.Column("issue_count", sa.Integer(), nullable=False),
        sa.Column("failure_reason", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_table(
        "indexed_files",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "index_id", sa.String(36), sa.ForeignKey("repository_indexes.id"), nullable=False
        ),
        sa.Column("path", sa.Text(), nullable=False),
        sa.Column("language", sa.String(50), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.UniqueConstraint("index_id", "path", name="uq_indexed_file_path"),
    )
    op.create_table(
        "code_symbols",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "index_id", sa.String(36), sa.ForeignKey("repository_indexes.id"), nullable=False
        ),
        sa.Column("symbol_key", sa.Text(), nullable=False),
        sa.Column("parent_key", sa.Text()),
        sa.Column("name", sa.String(500), nullable=False),
        sa.Column("qualified_name", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_start", sa.Integer(), nullable=False),
        sa.Column("line_end", sa.Integer(), nullable=False),
        sa.Column("column_start", sa.Integer(), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column("control_flow", sa.JSON(), nullable=False),
        sa.UniqueConstraint("index_id", "symbol_key", name="uq_index_symbol_key"),
    )
    op.create_table(
        "import_relations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "index_id", sa.String(36), sa.ForeignKey("repository_indexes.id"), nullable=False
        ),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("module", sa.Text()),
        sa.Column("imported_name", sa.Text()),
        sa.Column("alias", sa.String(500)),
        sa.Column("level", sa.Integer(), nullable=False),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("resolved_file_path", sa.Text()),
    )
    op.create_table(
        "call_relations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "index_id", sa.String(36), sa.ForeignKey("repository_indexes.id"), nullable=False
        ),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("caller_key", sa.Text()),
        sa.Column("callee_expression", sa.String(256), nullable=False),
        sa.Column("resolved_symbol_key", sa.Text()),
        sa.Column("line", sa.Integer(), nullable=False),
        sa.Column("column", sa.Integer(), nullable=False),
    )
    op.create_table(
        "index_parse_issues",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "index_id", sa.String(36), sa.ForeignKey("repository_indexes.id"), nullable=False
        ),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("line", sa.Integer()),
    )
    op.create_index("ix_repository_indexes_repository_id", "repository_indexes", ["repository_id"])
    op.create_index("ix_indexed_files_index_id", "indexed_files", ["index_id"])
    op.create_index("ix_code_symbols_index_id", "code_symbols", ["index_id"])
    op.create_index("ix_import_relations_index_id", "import_relations", ["index_id"])
    op.create_index("ix_call_relations_index_id", "call_relations", ["index_id"])
    op.create_index("ix_index_parse_issues_index_id", "index_parse_issues", ["index_id"])


def downgrade() -> None:
    op.drop_index("ix_index_parse_issues_index_id", table_name="index_parse_issues")
    op.drop_index("ix_call_relations_index_id", table_name="call_relations")
    op.drop_index("ix_import_relations_index_id", table_name="import_relations")
    op.drop_index("ix_code_symbols_index_id", table_name="code_symbols")
    op.drop_index("ix_indexed_files_index_id", table_name="indexed_files")
    op.drop_index("ix_repository_indexes_repository_id", table_name="repository_indexes")
    op.drop_table("index_parse_issues")
    op.drop_table("call_relations")
    op.drop_table("import_relations")
    op.drop_table("code_symbols")
    op.drop_table("indexed_files")
    op.drop_table("repository_indexes")
