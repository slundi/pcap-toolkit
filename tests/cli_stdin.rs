//! End-to-end tests for reading captures from standard input (`-`).
//!
//! These run the real binary with the capture piped into stdin, which is the
//! only way to exercise the `PacketSource::Stdin` path without touching the
//! test harness's own stdin.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Run the binary with `args`, writing `stdin_bytes` to its stdin.
fn run_with_stdin(args: &[&str], stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_pcap-toolkit"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn pcap-toolkit");
    {
        let mut stdin = child.stdin.take().expect("child stdin");
        // The child may exit early on a usage error and close the pipe; that
        // is the behaviour under test, so ignore BrokenPipe here.
        let _ = stdin.write_all(stdin_bytes);
    }
    child.wait_with_output().expect("wait for pcap-toolkit")
}

fn run(args: &[&str]) -> Output {
    run_with_stdin(args, &[])
}

fn stdout_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("valid JSON on stdout")
}

#[test]
fn stats_from_stdin_matches_file() {
    let path = fixture("mixed.pcap");
    let bytes = std::fs::read(&path).unwrap();

    let from_file = stdout_json(&run(&["stats", "--json", path.to_str().unwrap()]));
    let from_stdin = stdout_json(&run_with_stdin(&["stats", "--json", "-"], &bytes));

    assert!(from_file["packets"].as_u64().unwrap() > 0);
    assert_eq!(from_file, from_stdin);
}

#[test]
fn info_from_stdin() {
    let bytes = std::fs::read(fixture("dns_exchange.pcap")).unwrap();
    let output = run_with_stdin(&["info", "-"], &bytes);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.starts_with("Packets : "));
    assert!(!text.starts_with("Packets : 0\n"));
}

#[test]
fn export_stdin_to_stdout_jsonl() {
    let path = fixture("http_session.pcap");
    let bytes = std::fs::read(&path).unwrap();
    let expected = stdout_json(&run(&["stats", "--json", path.to_str().unwrap()]))["packets"]
        .as_u64()
        .unwrap();

    let output = run_with_stdin(&["export", "-"], &bytes);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<serde_json::Value> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len() as u64, expected);
    // Status goes to stderr so the JSON stream on stdout stays clean.
    assert!(String::from_utf8_lossy(&output.stderr).contains("Exported"));
}

#[test]
fn stdin_garbage_reports_unknown_magic() {
    let output = run_with_stdin(&["stats", "-"], b"definitely not a pcap");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("<stdin>"), "{stderr}");
    assert!(stderr.contains("unrecognised file magic"), "{stderr}");
}

#[test]
fn empty_stdin_reports_truncation() {
    let output = run(&["stats", "-"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("empty or truncated"), "{stderr}");
}

#[test]
fn sort_rejects_stdin() {
    let output = run(&["sort", "-o", "/dev/null", "-"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("seekable"));
}

#[test]
fn export_min_flow_packets_rejects_stdin() {
    let output = run(&["export", "--min-flow-packets", "2", "-"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--min-flow-packets"), "{stderr}");
    assert!(stderr.contains("stdin"), "{stderr}");
}
