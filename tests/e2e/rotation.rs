use super::support::{App, selection};

pub fn check(app: &App) {
    let first = selection("1", "1");
    app.output(&["put", "101", "rollout@example.com"], &first);
    app.expect(
        &["search", " ROLLOUT@EXAMPLE.COM "],
        &first,
        "Matches: [101]; rejected: 0.",
    );
    app.output(&["rotation-canary", "baseline.canary"], &first);

    // Readers learn E2 before either writer promotes it; index promotion is independent.
    app.output(
        &["rotation-canary", "encryption.canary"],
        &selection("2", "1"),
    );
    app.fail(&["rotation-ready", "encryption.canary"], &first);
    let staged = selection("staged", "1");
    app.expect(&["rotation-ready", "encryption.canary"], &staged, "Ready.");
    app.output(&["put", "102", "rollout@example.com"], &staged);
    app.expect(&["get", "102"], &first, "102: rollout@example.com");
    let encryption = selection("2", "1");
    app.output(&["put", "103", "rollout@example.com"], &encryption);
    app.output(&["put", "104", "rollout@example.com"], &staged);
    for config in [encryption, staged] {
        app.expect(&["get", "101"], &config, "101: rollout@example.com");
        app.expect(&["get", "103"], &config, "103: rollout@example.com");
        app.expect(
            &["search", "rollout@example.com"],
            &config,
            "Matches: [101, 102, 103, 104]; rejected: 0.",
        );
    }
    let current = selection("2", "2");
    app.output(&["rotation-canary", "index.canary"], &current);
    app.fail(&["rotation-ready", "index.canary"], &encryption);
    let staged_index = selection("2", "staged");
    app.expect(&["rotation-ready", "index.canary"], &staged_index, "Ready.");
    app.output(&["put", "105", "rollout@example.com"], &staged_index);
    app.expect(
        &["search", "rollout@example.com"],
        &encryption,
        "Matches: [101, 102, 103, 104, 105]; rejected: 0.",
    );
    app.output(&["put", "106", "rollout@example.com"], &current);
    app.output(&["put", "107", "rollout@example.com"], &staged_index);
    app.output(&["put", "108", "different@example.com"], &current);
    app.output(&["demo-false-candidate", "108", "106"], &current);
    for config in [current, staged_index] {
        app.expect(
            &["search", "rollout@example.com"],
            &config,
            "Matches: [101, 102, 103, 104, 105, 106, 107]; rejected: 1.",
        );
        for canary in ["baseline.canary", "encryption.canary", "index.canary"] {
            app.expect(&["rotation-ready", canary], &config, "Ready.");
        }
    }

    // Roll back write selection while retaining readability. Every command restarts.
    let rollback = selection("staged", "staged");
    app.expect(&["get", "106"], &rollback, "106: rollout@example.com");
    app.output(&["put", "109", "rollout@example.com"], &rollback);
    for config in [rollback, current] {
        app.expect(
            &["search", "rollout@example.com"],
            &config,
            "Matches: [101, 102, 103, 104, 105, 106, 107, 109]; rejected: 1.",
        );
    }
    let e1 = "a20b59cd-809b-4ff1-9776-4f4199687287";
    let e2 = "34d4431d-cec6-453c-9a62-bec73c872420";
    let i1 = "830040f0-0c49-4ab2-87e6-cb2184981776";
    let i2 = "bcce33bf-947f-42a5-9a83-0fd3d4c3050f";
    for (id, encryption, index) in [
        (101, e1, i1),
        (102, e1, i1),
        (103, e2, i1),
        (104, e1, i1),
        (105, e2, i1),
        (106, e2, i2),
        (107, e2, i1),
        (109, e1, i1),
    ] {
        app.expect(
            &["generations", &id.to_string()],
            &rollback,
            &format!("Encryption: {encryption}; index: {index}."),
        );
    }
    app.fail(&["get", "106"], &first);
    app.expect(
        &["search", "rollout@example.com"],
        &encryption,
        "Matches: [101, 102, 103, 104, 105, 107, 109]; rejected: 0.",
    );
    app.output(&["put", "108", "different@example.com"], &current);
    app.expect(
        &["search", "rollout@example.com"],
        &current,
        "Matches: [101, 102, 103, 104, 105, 106, 107, 109]; rejected: 0.",
    );
}
