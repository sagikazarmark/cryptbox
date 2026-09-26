use super::support::{App, selection};
use std::fs;

pub fn check(app: &mut App) {
    const CONFIGURATION_ERROR: &str =
        "Error: \"database configuration: DATABASE_URL must be valid UTF-8 and present\"";
    let absent = app
        .command(&["init"])
        .env_remove("DATABASE_URL")
        .output()
        .unwrap();
    assert!(!absent.status.success());
    assert!(absent.stdout.is_empty());
    assert_eq!(
        String::from_utf8(absent.stderr).unwrap().trim(),
        CONFIGURATION_ERROR
    );
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let invalid = app
            .command(&["init"])
            .env(
                "DATABASE_URL",
                OsString::from_vec(b"postgres://user:SYNTHETIC_PASSWORD\xff@localhost/db".to_vec()),
            )
            .output()
            .unwrap();
        assert!(!invalid.status.success());
        assert!(invalid.stdout.is_empty());
        assert_eq!(
            String::from_utf8(invalid.stderr).unwrap().trim(),
            CONFIGURATION_ERROR
        );
    }
    // Nullable updates must keep the ciphertext/index projection synchronized.
    app.output(&["put", "1", " Alice@Example.com "], &[]);
    app.expect(&["get", "1"], &[], "1:  Alice@Example.com");
    app.expect(
        &["search", "alice@example.com"],
        &[],
        "Matches: [1]; rejected: 0.",
    );
    app.output(&["put-null", "2"], &[]);
    app.expect(&["get", "2"], &[], "2: NULL");
    app.output(&["put", "2", "before@example.com"], &[]);
    app.output(&["put", "2", " Alice@Example.com "], &[]);
    app.expect(
        &["search", "before@example.com"],
        &[],
        "Matches: []; rejected: 0.",
    );
    app.expect(
        &["search", "alice@example.com"],
        &[],
        "Matches: [1, 2]; rejected: 0.",
    );
    app.output(&["put-null", "2"], &[]);
    app.expect(
        &["search", "alice@example.com"],
        &[],
        "Matches: [1]; rejected: 0.",
    );
    let current = selection("2", "2");
    app.output(&["put", "3", "alice@example.com"], &current);
    app.output(&["put", "4", "bob@example.com"], &current);
    app.output(&["demo-false-candidate", "4", "3"], &current);
    for config in [&[][..], &current[..]] {
        app.expect(
            &["search", " ALICE@EXAMPLE.COM "],
            config,
            "Matches: [1, 3]; rejected: 1.",
        );
    }
    assert!(
        app.fail(&["get", "1"], &[("CRYPTBOX_GENERATION", "3")])
            .contains("key configuration")
    );
    let key = app.keys.join("encryption-1.hex");
    let original = fs::read(&key).unwrap();
    for malformed in ["z".repeat(64), "00".to_owned()] {
        fs::write(&key, malformed).unwrap();
        assert!(app.fail(&["get", "1"], &[]).contains("key configuration"));
    }
    fs::write(&key, original).unwrap();
    app.expect(&["get", "1"], &[], "1:  Alice@Example.com");
    app.output(&["rotation-canary", "current.canary"], &current);
    for role in ["encryption", "index"] {
        let key = app.keys.join(format!("{role}-2.hex"));
        let original = fs::read(&key).unwrap();
        fs::write(&key, "ab".repeat(32)).unwrap();
        app.fail(&["rotation-ready", "current.canary"], &current);
        fs::write(key, original).unwrap();
        app.expect(&["rotation-ready", "current.canary"], &current, "Ready.");
    }
    assert!(
        app.fail(&["get", "1"], &[("CRYPTBOX_ENCRYPTION", "2")])
            .contains("set both")
    );
    assert!(
        app.fail(&["get", "1"], &selection("invalid", "1"))
            .contains("key configuration")
    );

    // SQLx's query macros compile against this scenario's actual schema.
    app.rebuild("macro-check");
    app.expect(&["macro-get", "1"], &current, "1:  Alice@Example.com");
    app.expect(&["macro-get", "2"], &current, "2: NULL");
    app.expect(&["macro-get", "3"], &current, "3: alice@example.com");
    app.expect(
        &["macro-put", "5", "macro@example.com"],
        &current,
        "Stored 5.",
    );
    assert_eq!(
        app.fail(&["macro-put", "5", "invalid address"], &current)
            .trim(),
        "Error: \"application email validation failed\""
    );
    app.expect(&["get", "5"], &current, "5: macro@example.com");
    app.expect(
        &["search", "MACRO@example.com"],
        &current,
        "Matches: [5]; rejected: 0.",
    );
}
