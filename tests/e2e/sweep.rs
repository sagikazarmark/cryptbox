use super::support::{App, selection};

pub fn check(app: &App) {
    let keys = selection("2", "2");
    for id in [10, 20, 30] {
        app.output(&["put", &id.to_string(), "sweep@example.com"], &[]);
    }
    app.output(&["put", "40", "sweep@example.com"], &keys);
    app.expect(&["sweep-status", "rotation-2"], &keys, "Checkpoint: None.");
    app.expect(
        &["sweep-batch", "rotation-2"],
        &keys,
        "Checkpoint: Some(20); current: 0; stale: 2; conflicts: 0.",
    );
    app.expect(
        &["sweep-status", "rotation-2"],
        &keys,
        "Checkpoint: Some(20).",
    );
    // Exit after writes, before persisting the cursor; replay in a new process.
    app.expect(
        &["sweep-uncheckpointed", "rotation-2"],
        &keys,
        "Checkpoint: Some(40); current: 1; stale: 1; conflicts: 0.",
    );
    app.expect(
        &["sweep-status", "rotation-2"],
        &keys,
        "Checkpoint: Some(20).",
    );
    app.expect(
        &["sweep-batch", "rotation-2"],
        &keys,
        "Checkpoint: Some(40); current: 2; stale: 0; conflicts: 0.",
    );
    app.expect(
        &["sweep-batch", "rotation-2"],
        &keys,
        "Checkpoint: None; current: 0; stale: 0; conflicts: 0.",
    );
    app.expect(
        &["sweep-verify", "rotation-2"],
        &keys,
        "Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.",
    );
    app.output(&["put", "10", "sweep@example.com"], &[]);
    app.expect(
        &["sweep-batch", "rotation-2"],
        &keys,
        "Checkpoint: None; current: 0; stale: 0; conflicts: 0.",
    );
    app.expect(
        &["sweep-verify", "rotation-2"],
        &keys,
        "Complete: false; current: 3; stale: 1; legacy: 0; malformed: 0.",
    );
    // A new run identity repairs a stale write behind the durable cursor.
    app.expect(
        &["sweep-batch", "rotation-2-repair-1"],
        &keys,
        "Checkpoint: Some(20); current: 1; stale: 1; conflicts: 0.",
    );
    for _ in 0..2 {
        app.output(&["sweep-batch", "rotation-2-repair-1"], &keys);
    }
    app.expect(
        &["sweep-verify", "rotation-2-repair-1"],
        &keys,
        "Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.",
    );
    let third = selection("3", "3");
    let staged = selection("staged-3", "staged-3");
    app.output(&["rotation-canary", "third.canary"], &third);
    app.expect(&["rotation-ready", "third.canary"], &staged, "Ready.");
    app.expect(
        &["sweep-conflict", "rotation-3"],
        &third,
        "Stored 10.\nConflicts: 1.",
    );
    app.expect(&["get", "10"], &staged, "10: concurrent@example.com");
    app.expect(
        &["search", "CONCURRENT@example.com"],
        &staged,
        "Matches: [10]; rejected: 0.",
    );
    for config in [staged, third] {
        app.expect(
            &["search", "SWEEP@example.com"],
            &config,
            "Matches: [20, 30, 40]; rejected: 0.",
        );
    }
    app.expect(&["sweep-status", "rotation-3"], &third, "Checkpoint: None.");
    app.fail(&["sweep-batch", "missing-key-rehearsal"], &keys);
    app.expect(
        &["sweep-status", "missing-key-rehearsal"],
        &third,
        "Checkpoint: None.",
    );
    app.expect(&["sweep-status", "rotation-3"], &third, "Checkpoint: None.");
    app.expect(
        &["sweep-batch", "rotation-3"],
        &third,
        "Checkpoint: Some(20); current: 1; stale: 1; conflicts: 0.",
    );
    app.expect(
        &["search", "SWEEP@example.com"],
        &staged,
        "Matches: [20, 30, 40]; rejected: 0.",
    );
    app.expect(
        &["sweep-batch", "rotation-3"],
        &third,
        "Checkpoint: Some(40); current: 0; stale: 2; conflicts: 0.",
    );
    app.output(&["sweep-batch", "rotation-3"], &third);
    app.expect(
        &["sweep-verify", "rotation-3"],
        &third,
        "Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.",
    );
    app.expect(
        &["search", "SWEEP@example.com"],
        &staged,
        "Matches: [20, 30, 40]; rejected: 0.",
    );
    for id in [20, 30, 40] {
        app.expect(
            &["get", &id.to_string()],
            &staged,
            &format!("{id}: sweep@example.com"),
        );
    }
}
