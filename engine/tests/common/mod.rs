// Copyright (c) Microsoft. All rights reserved.

//! Shared helpers for integration tests that read files outside the
//! `engine/` package directory (the specification, the conformance
//! corpora, the examples). Those files are not part of the published
//! crate, so a test that needs them explains why it cannot run instead
//! of failing on a missing path.

use std::path::{Path, PathBuf};

/// The repository root, resolved as the parent of `CARGO_MANIFEST_DIR`.
///
/// Panics with an explanation when the parent is not the repository
/// checkout, which is the case when the tests run from a packaged
/// crate (`cargo test` inside the `.crate` tarball).
pub fn repo_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the engine package lives one level below the repository root")
        .to_path_buf();
    let marker = root.join("spec").join("SPECIFICATION.md");
    assert!(
        marker.is_file(),
        "this test reads files outside the engine package ({} is missing); \
         it needs the repository checkout and cannot run from a packaged crate",
        marker.display()
    );
    root
}
