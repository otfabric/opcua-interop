//! `test`: the adapter's self-test inside the image.
//!
//! The Rust unit tests (`cargo test`) run when the image is built; this
//! command repeats the checks that depend on the runtime inputs: every
//! fixture under `/fixtures` (or given with `--fixture`) is loaded and checked
//! against what the server can build ([crate::server::fixture_problems]), and
//! the capabilities document is checked against the operations the client
//! dispatches. Exit 0 when everything passes, 1 otherwise.

use std::path::{Path, PathBuf};

fn find_fixtures(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<_> = entries.flatten().map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            // fixtures/schema holds the JSON Schema, not a fixture.
            if p.file_name().is_some_and(|n| n != "schema") {
                find_fixtures(&p, out);
            }
        } else if p.file_name().is_some_and(|n| n == "fixture.json") {
            out.push(p);
        }
    }
}

fn check_capabilities() -> Vec<String> {
    let caps = crate::caps::document();
    let mut p = Vec::new();
    for key in [
        "schemaVersion", "adapter", "stack", "fixtureSchemaVersions", "roles", "transports",
        "encodings", "clientOperations", "serverServices", "securityProfiles", "userTokenTypes",
    ] {
        if caps.get(key).is_none() {
            p.push(format!("print-capabilities: {key} missing"));
        }
    }
    let ops: Vec<&str> = caps["clientOperations"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    for op in crate::client::OPERATIONS {
        if !ops.contains(&op) {
            p.push(format!("print-capabilities: client operation {op} not declared"));
        }
    }
    if ops.contains(&"codec") {
        p.push("print-capabilities: codec is declared but not provided".into());
    }
    for sp in caps["securityProfiles"].as_array().into_iter().flatten() {
        let policy = sp["policy"].as_str().unwrap_or_default();
        if crate::client::policy_from_name(policy).is_err() {
            p.push(format!("print-capabilities: security policy {policy} is not implemented"));
        }
    }
    p
}

pub fn run(args: &[String]) -> i32 {
    let mut fixtures: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match (args[i].as_str(), args.get(i + 1)) {
            ("--fixture", Some(v)) => {
                fixtures.push(PathBuf::from(v));
                i += 2;
            }
            (other, _) => {
                eprintln!("[async-opcua] test: unknown argument {other} (usage: test [--fixture <path>]...)");
                return 1;
            }
        }
    }
    if fixtures.is_empty() {
        find_fixtures(Path::new("/fixtures"), &mut fixtures);
    }

    let mut failures = 0;
    let mut report = |what: &str, problems: Vec<String>| {
        if problems.is_empty() {
            eprintln!("[async-opcua] test: OK   {what}");
        } else {
            failures += 1;
            eprintln!("[async-opcua] test: FAIL {what}");
            for p in problems {
                eprintln!("[async-opcua] test:      {p}");
            }
        }
    };

    report("capabilities", check_capabilities());
    if fixtures.is_empty() {
        eprintln!("[async-opcua] test: no fixture under /fixtures (mount the fixtures directory to check them)");
    }
    for f in &fixtures {
        let what = format!("fixture {}", f.display());
        match crate::fixture::load(&f.to_string_lossy()) {
            Ok(fx) => {
                let mut problems = crate::fixture::problems(&fx);
                problems.extend(crate::server::fixture_problems(&fx));
                report(&what, problems);
            }
            Err(e) => report(&what, vec![e]),
        }
    }
    if failures == 0 {
        eprintln!("[async-opcua] self-test: OK");
        0
    } else {
        eprintln!("[async-opcua] self-test: {failures} check(s) failed");
        1
    }
}
