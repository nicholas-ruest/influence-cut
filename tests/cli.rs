use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn executable_plan_is_json_and_exits_zero() {
    let output = Command::cargo_bin("influence-cut")
        .unwrap()
        .args([
            "plan",
            "--graph",
            "examples/agent-state.json",
            "--request",
            "examples/revoke-preference.json",
            "--format",
            "json",
        ])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let plan: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(plan["executable"], true);
    assert_eq!(plan["clean_checkpoint"], "checkpoint-0");
    assert_eq!(plan["affected_ids"].as_array().unwrap().len(), 5);
    assert!(plan["digest"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn blocked_plan_exits_two_and_explains_why() {
    Command::cargo_bin("influence-cut")
        .unwrap()
        .args([
            "plan",
            "--graph",
            "examples/agent-state-with-effect.json",
            "--request",
            "examples/revoke-preference.json",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("BLOCKED"))
        .stdout(predicate::str::contains("committed_effect"))
        .stdout(predicate::str::contains("email-sent"));
}

#[test]
fn validate_rejects_unknown_fields() {
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        file.path(),
        r#"{"schema_version":1,"nodes":[],"surprise":true}"#,
    )
    .unwrap();
    Command::cargo_bin("influence-cut")
        .unwrap()
        .args(["validate", "--graph", file.path().to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("unknown field"));
}

#[test]
fn validate_accepts_the_example_graph() {
    Command::cargo_bin("influence-cut")
        .unwrap()
        .args(["validate", "--graph", "examples/agent-state.json"])
        .assert()
        .success()
        .stdout("VALID nodes=7\n");
}
