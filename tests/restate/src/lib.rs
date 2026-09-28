//! End-to-end tests of `cryptbox::restate` against a real `restate-server`.
//!
//! The tests live in `tests/`. They are ignored by default: run them with
//! `RESTATE_SERVER_BIN` naming a `restate-server` binary, or with
//! `RESTATE_ADMIN_URL` and `RESTATE_INGRESS_URL` naming a running server, and
//! `--ignored`. See `restate-e2e-harness` for the server gate.
