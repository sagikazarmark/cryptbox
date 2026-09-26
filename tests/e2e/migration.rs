use super::support::{App, selection};

pub fn check(app: &mut App) {
    let keys = selection("2", "2");
    app.expect(&["migration-seed"], &keys, "Mixed-format fixture ready.");
    app.expect(
        &["migration-search", " MIXED@example.com "],
        &keys,
        "Matches: [10, 20, 30, 40, 50, 60]; rejected: 1.",
    );
    for id in [10, 20, 30, 40, 50, 60] {
        app.expect(
            &["migration-get", &id.to_string()],
            &keys,
            &format!("{id}: mixed@example.com"),
        );
    }
    app.output(&["migration-damage"], &keys);
    assert!(
        app.fail(&["sweep-batch", "legacy-2"], &keys)
            .contains("AuthenticationFailed")
    );
    app.expect(&["sweep-status", "legacy-2"], &keys, "Checkpoint: None.");
    app.fail(&["migration-search", "mixed@example.com"], &keys);
    app.expect(
        &["migration-quarantine"],
        &keys,
        "Quarantined 20; closure blocked.",
    );
    assert!(
        app.fail(&["migration-search", "mixed@example.com"], &keys)
            .contains("unresolved quarantine")
    );
    assert!(
        app.fail(&["migration-close"], &keys)
            .contains("unresolved quarantine")
    );
    app.expect(
        &["migration-restore"],
        &keys,
        "Restored 20 from approved fixture source.",
    );
    assert_eq!(
        app.fail(&["migration-restore"], &keys).trim(),
        "Error: \"database operation failed\""
    );
    app.expect(
        &["sweep-batch", "legacy-2"],
        &keys,
        "Checkpoint: Some(20); current: 2; stale: 0; conflicts: 0.",
    );
    app.expect(
        &["sweep-uncheckpointed", "legacy-2"],
        &keys,
        "Checkpoint: Some(40); current: 1; stale: 1; conflicts: 0.",
    );
    app.expect(
        &["sweep-status", "legacy-2"],
        &keys,
        "Checkpoint: Some(20).",
    );
    app.expect(
        &["sweep-batch", "legacy-2"],
        &keys,
        "Checkpoint: Some(40); current: 2; stale: 0; conflicts: 0.",
    );
    app.fail(&["migration-classify", "60"], &keys);
    app.fail(&["sweep-batch", "legacy-2"], &keys);
    app.expect(
        &["sweep-status", "legacy-2"],
        &keys,
        "Checkpoint: Some(40).",
    );
    app.expect(
        &["migration-repair-missing"],
        &keys,
        "Backfilled missing projection on row 50.",
    );
    app.fail(&["sweep-batch", "legacy-2"], &keys);
    app.expect(
        &["sweep-status", "legacy-2"],
        &keys,
        "Checkpoint: Some(40).",
    );
    app.expect(
        &["migration-repair-collision"],
        &keys,
        "Repaired discriminator-known row 60.",
    );
    app.expect(
        &["sweep-batch", "legacy-2"],
        &keys,
        "Checkpoint: Some(60); current: 2; stale: 0; conflicts: 0.",
    );
    for _ in 0..2 {
        app.output(&["sweep-batch", "legacy-2"], &keys);
    }
    app.expect(
        &["sweep-verify", "legacy-2"],
        &keys,
        "Complete: true; current: 7; stale: 0; legacy: 0; malformed: 0.",
    );
    app.expect(
        &["migration-search", "mixed@example.com"],
        &keys,
        "Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.",
    );
    // Converged generation metadata alone cannot establish index consistency.
    app.output(&["demo-false-candidate", "70", "40"], &keys);
    app.expect(
        &["migration-search", "mixed@example.com"],
        &keys,
        "Matches: [10, 20, 30, 40, 50, 60]; rejected: 1.",
    );
    assert!(
        app.output(&["sweep-verify", "legacy-2"], &keys)
            .contains("Complete: true")
    );
    assert!(
        app.fail(&["migration-close"], &keys)
            .contains("index consistency")
    );
    app.output(&["put", "70", "other@example.com"], &keys);
    app.expect(
        &["migration-close"],
        &keys,
        "Closure verified: 7 authenticated, validated, indexed rows.",
    );
    app.output(&["put", "40", " MiXeD@example.com "], &keys);
    app.expect(&["migration-get", "40"], &keys, "40:  MiXeD@example.com");
    app.expect(
        &["migration-search", "mixed@example.com"],
        &keys,
        "Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.",
    );
    app.expect(
        &["migration-close"],
        &keys,
        "Closure verified: 7 authenticated, validated, indexed rows.",
    );
    for invalid in [
        "missing-at",
        "inner space@example.com",
        "é@example.com",
        &format!("{}@example.com", "x".repeat(254)),
    ] {
        assert_eq!(
            app.fail(&["put", "40", invalid], &keys).trim(),
            "Error: \"application email validation failed\""
        );
        app.expect(&["migration-get", "40"], &keys, "40:  MiXeD@example.com");
    }
    app.output(&["put", "40", "mixed@example.com"], &keys);

    // Build a strict executable with no legacy handler compiled in, and delete its key.
    std::fs::remove_file(app.keys.join("legacy.hex")).unwrap();
    app.rebuild("");
    for id in [10, 20, 30, 40, 50, 60] {
        app.expect(
            &["get", &id.to_string()],
            &keys,
            &format!("{id}: mixed@example.com"),
        );
    }
    app.expect(
        &["search", "MIXED@example.com"],
        &keys,
        "Matches: [10, 20, 30, 40, 50, 60]; rejected: 0.",
    );
    app.expect(
        &["search", "OTHER@example.com"],
        &keys,
        "Matches: [70]; rejected: 0.",
    );
    app.output(&["put", "80", "strict@example.com"], &keys);
    app.expect(&["get", "80"], &keys, "80: strict@example.com");
    app.expect(
        &["search", "STRICT@example.com"],
        &keys,
        "Matches: [80]; rejected: 0.",
    );
    app.fail(&["migration-search", "mixed@example.com"], &keys);
}
