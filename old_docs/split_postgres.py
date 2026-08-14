#!/usr/bin/env python3
"""Move-only split of src/persistence/postgres.rs into postgres/ submodules.

Byte-exact line-range extraction (no reformatting), plus exactly three
mechanical transforms:
  1. top-level private `fn` / `async fn` / `const` become `pub(super)` so
     sibling submodules keep access (visibility stays inside the postgres
     module subtree; the crate's public API is unchanged);
  2. private inherent methods in rows.rs / labels.rs become `pub(super)`
     for the same reason (neither file contains trait impls);
  3. include_str! paths in migrations.rs gain one `../` for the new depth.

Run from the repo root: python3 split_postgres.py
Then: cargo test && cargo test --features "mobile-http postgres-adapter"
"""

import os
import sys

SRC = "src/persistence/postgres.rs"
OUT_DIR = "src/persistence/postgres"

# (filename, list of inclusive 1-indexed line ranges, bump_methods)
CHILDREN = [
    ("migrations.rs", [(17, 63)], False),
    ("types.rs", [(68, 108)], False),
    ("rows.rs", [(110, 446), (1594, 1676), (2699, 2856), (3006, 3513)], True),
    ("labels.rs", [(3514, 4234)], True),
    ("facade.rs", [(448, 487), (508, 885)], False),
    ("facts.rs", [(490, 494), (886, 1170), (1677, 1728), (2070, 2127)], False),
    ("workflow_tx.rs", [(65, 66), (1904, 2069)], False),
    ("episodes.rs", [(1789, 1846), (2128, 2278), (2328, 2404)], False),
    (
        "app_attest.rs",
        [(496, 500), (1171, 1288), (1525, 1593), (1847, 1881), (2405, 2698)],
        False,
    ),
    (
        "challenges.rs",
        [(502, 506), (1289, 1524), (1729, 1788), (1882, 1903), (2279, 2327)],
        False,
    ),
    ("support.rs", [(2857, 3005)], False),
]

SQLX_IMPORT = (
    '#[cfg(feature = "postgres-adapter")]\n'
    "#[allow(unused_imports)]\n"
    "use sqlx::{postgres::PgPoolOptions, postgres::PgRow, PgPool, Row};\n"
)

# Per-child import headers. Most children get `use super::*;`, which inherits
# the parent module's imports (including the parent's private glob imports of
# crate::persistence, crate::device, and crate::liveness — visible to child
# modules) plus the pub(super)-capped re-exports of sibling submodules.
SUPER_IMPORTS = {
    "migrations.rs": "",
    "app_attest.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "challenges.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "episodes.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "facade.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "facts.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "support.rs": "#[allow(unused_imports)]\nuse super::*;\n",
    "workflow_tx.rs": "#[allow(unused_imports)]\nuse super::*;\n",
}

HEADERS = {
    "migrations.rs": "",
    "types.rs": "",
    "rows.rs": "",
    "labels.rs": "",
    "facade.rs": (
        SQLX_IMPORT
        + '#[cfg(feature = "postgres-adapter")]\n'
        + "#[allow(unused_imports)]\n"
        + "use crate::flows::IdentityWorkflowSlice;\n"
        + '#[cfg(feature = "postgres-adapter")]\n'
        + "#[allow(unused_imports)]\n"
        + "use crate::identity::AccessDecisionResult;\n"
        + '#[cfg(feature = "postgres-adapter")]\n'
        + "#[allow(unused_imports)]\n"
        + "use crate::materialized::{materialize_identity_state, MaterializedIdentityState};\n"
        + '#[cfg(feature = "postgres-adapter")]\n'
        + "#[allow(unused_imports)]\n"
        + "use crate::policy::PolicyEvaluation;\n"
    ),
    "facts.rs": SQLX_IMPORT,
    "workflow_tx.rs": SQLX_IMPORT,
    "episodes.rs": SQLX_IMPORT,
    "app_attest.rs": SQLX_IMPORT,
    "challenges.rs": SQLX_IMPORT,
    "support.rs": (
        SQLX_IMPORT
        + '#[cfg(feature = "postgres-adapter")]\n'
        + "use std::future::Future;\n"
    ),
}

PARENT = """\
//! PostgreSQL adapter for the FEN identity model, split by stored entity and
//! concern. Move-only decomposition of the former single-file module; the
//! public API is unchanged (everything is re-exported below).

use super::*;
#[allow(unused_imports)]
use crate::device::*;
#[allow(unused_imports)]
use crate::liveness::*;

mod app_attest;
mod challenges;
mod episodes;
mod facade;
mod facts;
mod labels;
mod migrations;
mod rows;
mod support;
mod types;
mod workflow_tx;

#[cfg(feature = "postgres-adapter")]
pub use app_attest::*;
#[cfg(feature = "postgres-adapter")]
pub use challenges::*;
#[cfg(feature = "postgres-adapter")]
pub use facade::*;
#[cfg(feature = "postgres-adapter")]
pub use facts::*;
pub use migrations::*;
pub use rows::*;
pub use types::*;

#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use episodes::*;
#[allow(unused_imports)]
pub(super) use labels::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use support::*;
#[cfg(feature = "postgres-adapter")]
#[allow(unused_imports)]
pub(super) use workflow_tx::*;
"""

# Sanity anchors: (line number, expected prefix after stripping)
ANCHORS = [
    (17, "pub const IDENTITY_ENCRYPTED_FACTS_MIGRATION_SQL"),
    (66, "const IDENTITY_WORKFLOW_SEQUENCE_LOCK_KEY"),
    (110, "#[derive("),
    (448, "#[cfg("),
    (887, "impl SqlxPostgresEncryptedFactRepository"),
    (1594, "impl PostgresEncryptedFactRow"),
    (1905, "async fn insert_stored_workflow_slice_rows"),
    (2857, "#[cfg("),
    (3006, "impl PostgresMaterializationAuditRow"),
    (3514, "fn postgres_fact_status_parts"),
]


def transform(lines, bump_methods, filename):
    out = []
    for line in lines:
        if line.startswith("fn "):
            line = "pub(super) " + line
        elif line.startswith("async fn "):
            line = "pub(super) " + line
        elif line.startswith("const "):
            line = "pub(super) " + line
        elif bump_methods and line.startswith("    fn "):
            line = "    pub(super) " + line.lstrip(" ").replace("fn ", "fn ", 1)
            # rebuild precisely: original was '    fn ...'
        if filename == "migrations.rs":
            line = line.replace('include_str!("../../migrations/', 'include_str!("../../../migrations/')
        out.append(line)
    return out


def main():
    if not os.path.exists(SRC):
        sys.exit(f"missing {SRC}; run from the repo root")
    with open(SRC, encoding="utf-8") as f:
        lines = f.read().split("\n")
    # split('\n') gives a trailing '' if file ends with newline; normalize.
    if lines and lines[-1] == "":
        lines.pop()
    total = len(lines)
    if total != 4234:
        sys.exit(f"expected 4234 lines in {SRC}, found {total}; aborting (file drifted)")
    for number, prefix in ANCHORS:
        actual = lines[number - 1].lstrip()
        if not lines[number - 1].startswith(prefix) and not actual.startswith(prefix):
            sys.exit(
                f"anchor mismatch at line {number}: expected prefix {prefix!r}, "
                f"found {lines[number - 1]!r}; aborting"
            )

    # Coverage check: every range used exactly once, no overlaps.
    used = [False] * (total + 1)
    for _, ranges, _ in CHILDREN:
        for start, end in ranges:
            for index in range(start, end + 1):
                if used[index]:
                    sys.exit(f"line {index} assigned twice; aborting")
                used[index] = True

    os.makedirs(OUT_DIR, exist_ok=True)
    for filename, ranges, bump_methods in CHILDREN:
        body = []
        for start, end in ranges:
            body.extend(lines[start - 1 : end])
            body.append("")  # blank line between ranges
        while body and body[-1] == "":
            body.pop()
        body = transform(body, bump_methods, filename)
        header = HEADERS[filename]
        content = SUPER_IMPORTS.get(filename, "use super::*;\n")
        if header:
            content += header
        content += "\n" + "\n".join(body) + "\n"
        path = os.path.join(OUT_DIR, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"wrote {path} ({len(body)} lines)")

    with open(SRC, "w", encoding="utf-8") as f:
        f.write(PARENT)
    print(f"rewrote {SRC} as module parent")
    print("done; now run the cargo checks")


if __name__ == "__main__":
    main()
