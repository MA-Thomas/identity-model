use std::fs;
use std::path::{Path, PathBuf};

#[test]
fn enum_string_label_helpers_stay_in_boundary_modules() {
    let mut files = Vec::new();
    collect_rust_files(Path::new("src"), &mut files);

    for file in files {
        let source = fs::read_to_string(&file).expect("source file should be readable");
        let path = normalized_path(&file);

        for line in source.lines() {
            if line.contains("fn ") && line.contains("_name(") {
                assert_eq!(
                    path, "src/fixtures/fixture_labels.rs",
                    "presentation enum labels should stay in fixture_labels.rs: {path}: {line}"
                );
            }

            if line.contains("fn ") && line.contains("_canonical_label(") {
                assert_eq!(
                    path, "src/continuity/canonical.rs",
                    "canonical enum labels should stay in continuity/canonical.rs: {path}: {line}"
                );
            }

            if line.contains("fn access_authorization_label(") {
                assert_eq!(
                    path, "src/flows/episode_labels.rs",
                    "episode labels should stay in flows/episode_labels.rs: {path}: {line}"
                );
            }
        }
    }
}

#[test]
fn modules_do_not_use_legacy_mod_rs_entrypoints() {
    let mut files = Vec::new();
    collect_rust_files(Path::new("src"), &mut files);

    assert!(
        files
            .iter()
            .all(|file| file.file_name().is_none_or(|name| name != "mod.rs")),
        "module entrypoints should use sibling files like src/flows.rs, not mod.rs"
    );
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(path).expect("source directory should be readable") {
        let entry = entry.expect("source entry should be readable");
        let path = entry.path();

        if path.is_dir() {
            collect_rust_files(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

fn normalized_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
