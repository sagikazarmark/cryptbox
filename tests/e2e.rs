//! Process-level workflows against the documented application and durable storage.
//! PostgreSQL cases require a disposable `DATABASE_URL` and `--include-ignored`.

// Keep ordered process-level rehearsals readable as complete workflows.
#![allow(clippy::too_many_lines)]

#[cfg(all(
    feature = "migrate",
    any(feature = "sqlx-sqlite", feature = "sqlx-postgres")
))]
#[path = "e2e/migration.rs"]
mod migration;
#[cfg(all(feature = "migrate", feature = "sqlx-sqlite"))]
#[path = "e2e/recovery.rs"]
mod recovery;
#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
#[path = "e2e/rotation.rs"]
mod rotation;
#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
#[path = "e2e/searchable.rs"]
mod searchable;
#[path = "e2e/support.rs"]
mod support;
#[cfg(all(
    feature = "migrate",
    any(feature = "sqlx-sqlite", feature = "sqlx-postgres")
))]
#[path = "e2e/sweep.rs"]
mod sweep;

#[cfg(any(feature = "sqlx-sqlite", feature = "sqlx-postgres"))]
use support::App;

#[test]
#[cfg(feature = "sqlx-sqlite")]
fn sqlite_searchable() {
    searchable::check(&mut App::new("sqlite", ""));
}

#[test]
#[cfg(feature = "sqlx-sqlite")]
fn sqlite_rotation() {
    rotation::check(&App::new("sqlite", ""));
}

#[test]
#[cfg(all(feature = "sqlx-sqlite", feature = "migrate"))]
fn sqlite_sweep() {
    sweep::check(&App::new("sqlite", "maintenance"));
}

#[test]
#[cfg(all(feature = "sqlx-sqlite", feature = "migrate"))]
fn sqlite_migration() {
    migration::check(&mut App::new("sqlite", "legacy-migration"));
}

#[test]
#[cfg(all(feature = "sqlx-sqlite", feature = "migrate"))]
fn sqlite_recovery() {
    recovery::check(&App::new("sqlite", "maintenance"));
}

#[test]
#[cfg(feature = "sqlx-postgres")]
#[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
fn postgres_searchable() {
    searchable::check(&mut App::new("postgres", ""));
}

#[test]
#[cfg(feature = "sqlx-postgres")]
#[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
fn postgres_rotation() {
    rotation::check(&App::new("postgres", ""));
}

#[test]
#[cfg(all(feature = "sqlx-postgres", feature = "migrate"))]
#[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
fn postgres_sweep() {
    sweep::check(&App::new("postgres", "maintenance"));
}

#[test]
#[cfg(all(feature = "sqlx-postgres", feature = "migrate"))]
#[ignore = "requires a disposable PostgreSQL DATABASE_URL"]
fn postgres_migration() {
    migration::check(&mut App::new("postgres", "legacy-migration"));
}

#[test]
fn diagnostics_expose_only_allowlisted_fields() {
    let scratch = support::Scratch::new();
    let binary = support::build(&scratch.0, "diagnostics", "", None);
    let output = std::process::Command::new(binary).output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "field_id=ca274e85-63c4-4f7d-a255-2dfecbfe5e25 field_name=user-email operation=decrypt error=authentication_failed\n"
    );
    assert!(output.stderr.is_empty());
}

#[test]
#[cfg(feature = "sqlx-sqlite")]
fn automatic_contexts_are_isolated_between_processes() {
    let scratch = support::Scratch::new();
    let binary = support::build(&scratch.0, "automatic", "sqlite", None);
    let children: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|fixture| {
            std::process::Command::new(&binary)
                .arg(fixture)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"Automatic adapter round trip succeeded.\n");
        assert!(output.stderr.is_empty());
    }
}
