use super::support::{App, selection};
use std::fs;

pub fn check(app: &App) {
    let historical = selection("1", "1");
    let compatible = selection("2", "2");
    let online = selection("2-only", "2-only");
    for id in [10, 20] {
        app.output(
            &["put", &id.to_string(), "recovery@example.com"],
            &historical,
        );
    }
    app.output(&["rotation-canary", "baseline.canary"], &historical);
    let backup = app.scratch.0.join("before-rotation.db");
    app.expect(
        &["recovery-copy", backup.to_str().unwrap()],
        &historical,
        "Database copy saved.",
    );
    app.fail(&["recovery-copy", backup.to_str().unwrap()], &historical);
    let backup_bytes = fs::read(&backup).unwrap();
    let recovery_keys = app.scratch.0.join("recovery-keys");
    fs::create_dir(&recovery_keys).unwrap();
    for role in ["encryption", "index"] {
        fs::copy(
            app.keys.join(format!("{role}-1.hex")),
            recovery_keys.join(format!("{role}-1.hex")),
        )
        .unwrap();
    }
    let preflight_path = app.scratch.0.join("preflight.db");
    fs::copy(&backup, &preflight_path).unwrap();
    let preflight_url = format!("sqlite://{}?mode=rw", preflight_path.display());
    let preflight = [
        historical[0],
        historical[1],
        ("DATABASE_URL", &preflight_url),
        ("CRYPTBOX_KEY_DIR", recovery_keys.to_str().unwrap()),
    ];
    app.expect(&["rotation-ready", "baseline.canary"], &preflight, "Ready.");
    for id in [10, 20] {
        app.expect(
            &["get", &id.to_string()],
            &preflight,
            &format!("{id}: recovery@example.com"),
        );
    }
    app.expect(
        &["audit-current"],
        &preflight,
        "Audited: 2 authenticated, current-index rows.",
    );
    app.expect(
        &["search", " RECOVERY@EXAMPLE.COM "],
        &preflight,
        "Matches: [10, 20]; rejected: 0.",
    );
    app.expect(
        &["rotation-ready", "baseline.canary"],
        &historical,
        "Ready.",
    );
    app.output(&["rotation-canary", "target.canary"], &compatible);
    app.expect(
        &["rotation-ready", "target.canary"],
        &selection("staged", "staged"),
        "Ready.",
    );
    app.output(&["put", "30", "recovery@example.com"], &compatible);
    app.output(&["put", "40", "different@example.com"], &compatible);
    for _ in 0..3 {
        app.output(&["sweep-batch", "retire-2"], &compatible);
    }
    app.expect(
        &["sweep-verify", "retire-2"],
        &compatible,
        "Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.",
    );
    app.expect(
        &["audit-current"],
        &compatible,
        "Audited: 4 authenticated, current-index rows.",
    );
    app.output(&["demo-false-candidate", "40", "30"], &compatible);
    app.expect(
        &["sweep-verify", "retire-2"],
        &compatible,
        "Complete: true; current: 4; stale: 0; legacy: 0; malformed: 0.",
    );
    app.fail(&["audit-current"], &compatible);
    app.output(&["put", "40", "different@example.com"], &compatible);
    app.expect(
        &["audit-current"],
        &compatible,
        "Audited: 4 authenticated, current-index rows.",
    );

    // Historical roots are physically absent from the online deployment.
    for role in ["encryption", "index"] {
        let original = app.keys.join(format!("{role}-1.hex"));
        assert_eq!(
            fs::read(&original).unwrap(),
            fs::read(recovery_keys.join(format!("{role}-1.hex"))).unwrap()
        );
        fs::remove_file(original).unwrap();
    }
    app.expect(
        &["audit-current"],
        &online,
        "Audited: 4 authenticated, current-index rows.",
    );
    app.expect(
        &["search", "RECOVERY@example.com"],
        &online,
        "Matches: [10, 20, 30]; rejected: 0.",
    );
    app.fail(&["rotation-ready", "baseline.canary"], &online);
    app.fail(&["get", "10"], &compatible);

    // A fresh restore after removal needs both historical encryption and index keys.
    let restored = app.scratch.0.join("isolated-recovery.db");
    fs::copy(&backup, &restored).unwrap();
    let restored_url = format!("sqlite://{}?mode=rw", restored.display());
    let recovery = [
        historical[0],
        historical[1],
        ("DATABASE_URL", &restored_url),
        ("CRYPTBOX_KEY_DIR", recovery_keys.to_str().unwrap()),
    ];
    app.expect(&["rotation-ready", "baseline.canary"], &recovery, "Ready.");
    app.fail(
        &["get", "10"],
        &[online[0], online[1], ("DATABASE_URL", &restored_url)],
    );
    for id in [10, 20] {
        app.expect(
            &["get", &id.to_string()],
            &recovery,
            &format!("{id}: recovery@example.com"),
        );
    }
    app.fail(&["get", "30"], &recovery);
    app.expect(
        &["audit-current"],
        &recovery,
        "Audited: 2 authenticated, current-index rows.",
    );
    app.expect(
        &["search", " RECOVERY@EXAMPLE.COM "],
        &recovery,
        "Matches: [10, 20]; rejected: 0.",
    );
    fs::copy(
        app.keys.join("index-2.hex"),
        recovery_keys.join("index-2.hex"),
    )
    .unwrap();
    let mut missing_probe = recovery;
    missing_probe[1] = ("CRYPTBOX_INDEX", "2-only");
    app.expect(&["get", "10"], &missing_probe, "10: recovery@example.com");
    app.expect(
        &["search", "recovery@example.com"],
        &missing_probe,
        "Matches: []; rejected: 0.",
    );
    app.fail(&["audit-current"], &missing_probe);
    app.expect(&["get", "30"], &online, "30: recovery@example.com");
    app.expect(
        &["search", "RECOVERY@example.com"],
        &online,
        "Matches: [10, 20, 30]; rejected: 0.",
    );
    assert_eq!(fs::read(backup).unwrap(), backup_bytes);
}
