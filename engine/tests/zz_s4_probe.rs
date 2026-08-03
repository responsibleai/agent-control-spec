#![cfg(feature = "rego")]
//! TEMPORARY stage-4 review probes. Delete this file.

use agent_control_spec::{
    canonical_json, JsonValue, PolicyDispatcher, PreparedPolicyInvocation, RegoPolicyInvocation,
    RegorusPolicyDispatcher, RegorusRegoRunner,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn rego_invocation(
    query: &str,
    bundle: Option<String>,
    adapter_config: BTreeMap<String, JsonValue>,
    input: JsonValue,
) -> PreparedPolicyInvocation {
    PreparedPolicyInvocation::Rego(RegoPolicyInvocation {
        query: query.to_string(),
        bundle,
        adapter_config,
        canonical_input: canonical_json(&input).unwrap(),
        input,
    })
}

fn dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("zz-s4")
        .join(format!("{name}-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

/// B: full input domain for bundle-scope data selection.
#[test]
fn zz_b_bundle_scope_domain() {
    let d = dir("b-domain");
    fs::create_dir_all(d.join("nested")).unwrap();
    fs::create_dir_all(d.join("caseup")).unwrap();
    fs::create_dir_all(d.join("casestem")).unwrap();
    fs::create_dir_all(d.join("a/b/c")).unwrap();
    fs::create_dir_all(d.join("v1.2")).unwrap();
    fs::write(d.join("p.rego"), "package t\nimport rego.v1\nv := 1\n").unwrap();
    fs::write(d.join("database.json"), r#"{"prefix_collision": true}"#).unwrap();
    fs::write(d.join("nested").join("data.yml"), "ymlk: 11\n").unwrap();
    fs::write(d.join("caseup").join("data.YAML"), "upk: 12\n").unwrap();
    fs::write(d.join("casestem").join("DATA.yaml"), "stemk: 13\n").unwrap();
    fs::write(d.join("a/b/c").join("data.json"), r#"{"deep": 14}"#).unwrap();
    fs::write(d.join("v1.2").join("data.json"), r#"{"dotted": 15}"#).unwrap();
    let bundle = d.display().to_string();
    let disp = RegorusPolicyDispatcher::new();
    let eval = |q: &str| {
        disp.evaluate(&rego_invocation(
            q,
            Some(bundle.clone()),
            BTreeMap::new(),
            json!({}),
        ))
    };
    println!(
        "database.json (opa: IGNORED)      -> {:?}",
        eval("data.prefix_collision")
    );
    println!(
        "nested/data.yml (opa: 11)         -> {:?}",
        eval("data.nested.ymlk")
    );
    println!(
        "caseup/data.YAML (opa: IGNORED)   -> {:?}",
        eval("data.caseup.upk")
    );
    println!(
        "casestem/DATA.yaml (opa: IGNORED) -> {:?}",
        eval("data.casestem.stemk")
    );
    println!(
        "a/b/c/data.json (opa: 14)         -> {:?}",
        eval("data.a.b.c.deep")
    );
    println!(
        "v1.2/data.json (opa: 15)          -> {:?}",
        eval("data[\"v1.2\"].dotted")
    );
}

/// B: non-object data documents.
#[test]
fn zz_b_non_object_documents() {
    // nested array (opa: data.nested == [1,2,3])
    let d = dir("b-array-nested");
    fs::create_dir_all(d.join("nested")).unwrap();
    fs::write(d.join("p.rego"), "package t\nimport rego.v1\nv := 1\n").unwrap();
    fs::write(d.join("nested").join("data.json"), "[1,2,3]").unwrap();
    let disp = RegorusPolicyDispatcher::new();
    println!(
        "nested array (opa: [1,2,3])  -> {:?}",
        disp.evaluate(&rego_invocation(
            "data.nested",
            Some(d.display().to_string()),
            BTreeMap::new(),
            json!({})
        ))
    );

    // root-level array via single data_paths file (opa: hard error)
    let d2 = dir("b-array-root");
    fs::write(d2.join("arr.json"), "[1,2,3]").unwrap();
    let mut cfg = BTreeMap::new();
    cfg.insert(
        "data_paths".to_string(),
        json!([d2.join("arr.json").display().to_string()]),
    );
    println!(
        "root array (opa: ERROR)      -> {:?}",
        disp.evaluate(&rego_invocation("data", None, cfg, json!({})))
    );

    // nested scalar
    let d3 = dir("b-scalar-nested");
    fs::create_dir_all(d3.join("nested")).unwrap();
    fs::write(d3.join("p.rego"), "package t\nimport rego.v1\nv := 1\n").unwrap();
    fs::write(d3.join("nested").join("data.json"), "42").unwrap();
    println!(
        "nested scalar (opa: 42)      -> {:?}",
        disp.evaluate(&rego_invocation(
            "data.nested",
            Some(d3.display().to_string()),
            BTreeMap::new(),
            json!({})
        ))
    );
}

/// B: two documents mounting at the same path with conflicting keys.
#[test]
fn zz_b_conflicting_mounts() {
    let d = dir("b-conflict");
    fs::create_dir_all(d.join("nested")).unwrap();
    fs::write(d.join("p.rego"), "package t\nimport rego.v1\nv := 1\n").unwrap();
    fs::write(d.join("nested").join("a.json"), r#"{"k": 1}"#).unwrap();
    fs::write(d.join("nested").join("b.json"), r#"{"k": 2}"#).unwrap();
    let mut cfg = BTreeMap::new();
    cfg.insert("data_paths".to_string(), json!([d.display().to_string()]));
    println!(
        "conflict (opa: merge error)  -> {:?}",
        RegorusPolicyDispatcher::new().evaluate(&rego_invocation(
            "data.nested.k",
            None,
            cfg,
            json!({})
        ))
    );
}

/// C: does legitimate concurrency hit the MAX_LIVE_WORKERS ceiling?
#[test]
fn zz_c_legitimate_concurrency() {
    for n in [32usize, 64, 65, 128] {
        let disp = Arc::new(RegorusPolicyDispatcher::with_runner(
            RegorusRegoRunner::new().with_eval_timeout(Duration::from_secs(30)),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(n));
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let disp = Arc::clone(&disp);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    disp.evaluate(&rego_invocation(
                        "count(numbers.range(0, 300000))",
                        None,
                        BTreeMap::new(),
                        json!({}),
                    ))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count();
        let saturated = results
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.detail().contains("saturated"))
            })
            .count();
        println!(
            "concurrency={n}: ok={ok} saturated={saturated} other_err={}",
            n - ok - saturated
        );
        if let Some(e) = results.iter().find_map(|r| r.as_ref().err()) {
            println!("   first error: {}", e.detail());
        }
    }
}

/// C: does the live counter return to baseline after a burst settles?
#[test]
fn zz_c_burst_settles() {
    fn threads() -> usize {
        fs::read_dir("/proc/self/task")
            .map(|e| e.count())
            .unwrap_or(0)
    }
    let disp = Arc::new(RegorusPolicyDispatcher::new());
    let before = threads();
    for round in 0..4 {
        let barrier = Arc::new(std::sync::Barrier::new(60));
        let handles: Vec<_> = (0..60)
            .map(|_| {
                let disp = Arc::clone(&disp);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    disp.evaluate(&rego_invocation("1 + 1", None, BTreeMap::new(), json!({})))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let sat = results
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.detail().contains("saturated"))
            })
            .count();
        println!("round {round}: saturated={sat} os_threads={}", threads());
        std::thread::sleep(Duration::from_millis(300));
        println!("   after settle: os_threads={}", threads());
    }
    println!("baseline before={before}");
}

/// E: does gathered print output accumulate in a cached runner?
#[test]
fn zz_e_print_accumulation() {
    let d = dir("e-prints");
    fs::write(
        d.join("p.rego"),
        r#"package t
import rego.v1
v := count([x | some i in numbers.range(0, 2000); print("leaking a fairly long line of print output ", i); x := i])
"#,
    )
    .unwrap();
    let bundle = d.display().to_string();
    let disp = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new()
            .with_policy_cache(true)
            .with_eval_timeout(Duration::from_secs(60)),
    );
    let rss = || -> i64 {
        fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmRSS:"))
                    .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            })
            .unwrap_or(-1)
    };
    let start = Instant::now();
    for i in 0..200 {
        let v = disp
            .evaluate(&rego_invocation(
                "data.t.v",
                Some(bundle.clone()),
                BTreeMap::new(),
                json!({}),
            ))
            .unwrap();
        if i % 50 == 0 {
            println!(
                "iter {i}: v={v} rss_kb={} elapsed={:?}",
                rss(),
                start.elapsed()
            );
        }
    }
    println!("final rss_kb={} elapsed={:?}", rss(), start.elapsed());
}

/// D: cost of cloning the runner per evaluation + cache sharing across clones.
#[test]
fn zz_d_clone_shares_cache() {
    let d = dir("d-clone");
    for i in 0..300 {
        fs::write(
            d.join(format!("p{i}.rego")),
            format!("package p{i}\nimport rego.v1\nv := {i}\n"),
        )
        .unwrap();
    }
    let runner = RegorusRegoRunner::new()
        .with_policy_cache(true)
        .with_eval_timeout(Duration::from_secs(60));
    let disp = RegorusPolicyDispatcher::with_runner(runner.clone());
    let bundle = d.display().to_string();
    let inv = || {
        rego_invocation(
            "data.p0.v",
            Some(bundle.clone()),
            BTreeMap::new(),
            json!({}),
        )
    };
    let t0 = Instant::now();
    disp.evaluate(&inv()).unwrap();
    let cold = t0.elapsed();
    let t1 = Instant::now();
    for _ in 0..20 {
        disp.evaluate(&inv()).unwrap();
    }
    let warm = t1.elapsed() / 20;
    // a clone of the runner should hit the SAME cache (Arc shared)
    let disp2 = RegorusPolicyDispatcher::with_runner(runner.clone());
    let t2 = Instant::now();
    disp2.evaluate(&inv()).unwrap();
    let clone_warm = t2.elapsed();
    println!("cold={cold:?} warm_avg={warm:?} clone_first={clone_warm:?}");
    assert!(runner.policy_cache_enabled());
}

/// F/4: does print() reach the host's stderr?
#[test]
fn zz_f_print_to_stderr() {
    let d = dir("f-print");
    fs::write(
        d.join("p.rego"),
        "package t\nimport rego.v1\nv := x if { print(\"SENTINEL_PRINT_LEAK\"); x := 1 }\n",
    )
    .unwrap();
    let out = RegorusPolicyDispatcher::new().evaluate(&rego_invocation(
        "data.t.v",
        Some(d.display().to_string()),
        BTreeMap::new(),
        json!({}),
    ));
    println!("print policy verdict: {out:?}");
}

/// Fix 3: is bundle loading inside the deadline?
#[test]
fn zz_f_load_inside_deadline() {
    let d = dir("f-load-deadline");
    for i in 0..1500 {
        fs::write(
            d.join(format!("p{i}.rego")),
            format!("package p{i}\nimport rego.v1\nv := {i}\n"),
        )
        .unwrap();
    }
    let disp = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new().with_eval_timeout(Duration::from_millis(50)),
    );
    let t = Instant::now();
    let r = disp.evaluate(&rego_invocation(
        "data.p0.v",
        Some(d.display().to_string()),
        BTreeMap::new(),
        json!({}),
    ));
    println!(
        "1500-file bundle, 50ms deadline: elapsed={:?} result={:?}",
        t.elapsed(),
        r.map(|_| "ok")
    );
}

/// C: one transient thread-spawn failure underflows the live counter and
/// wedges the pool permanently. Run under a low RLIMIT_NPROC.
#[test]
#[ignore]
fn zz_c_spawn_failure_wedges_pool() {
    let disp = RegorusPolicyDispatcher::new();
    let inv = || rego_invocation("1 + 1", None, BTreeMap::new(), json!({}));
    println!("healthy before: {:?}", disp.evaluate(&inv()));

    // Consume the process thread budget so the pool's spawn fails.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut held = Vec::new();
    loop {
        let stop = Arc::clone(&stop);
        match std::thread::Builder::new().spawn(move || {
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(5));
            }
        }) {
            Ok(h) => held.push(h),
            Err(e) => {
                println!("thread budget exhausted after {} threads: {e}", held.len());
                break;
            }
        }
        if held.len() > 20000 {
            println!("could not exhaust budget; run under prlimit --nproc");
            break;
        }
    }
    // Concurrent calls so the pool must SPAWN (not reuse the parked worker).
    let d2 = Arc::new(disp);
    let hs: Vec<_> = (0..4)
        .map(|_| {
            let d = Arc::clone(&d2);
            std::thread::Builder::new().spawn(move || {
                d.evaluate(&rego_invocation("1 + 1", None, BTreeMap::new(), json!({})))
            })
        })
        .collect();
    for h in hs {
        if let Ok(h) = h {
            println!("under pressure: {:?}", h.join().unwrap());
        } else {
            println!("under pressure: harness thread spawn failed too");
        }
    }
    let disp = Arc::try_unwrap(d2).ok();

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    for h in held {
        let _ = h.join();
    }
    std::thread::sleep(Duration::from_millis(200));

    let disp = disp.unwrap_or_else(RegorusPolicyDispatcher::new);
    for i in 0..3 {
        println!("after recovery #{i}: {:?}", disp.evaluate(&inv()));
    }
}

/// F: verify the module doc's enumerated divergences at HEAD.
#[test]
fn zz_f_doc_divergence_claims() {
    let disp = RegorusPolicyDispatcher::new();
    let eval = |q: &str| disp.evaluate(&rego_invocation(q, None, BTreeMap::new(), json!({})));
    for q in [
        "0.1 + 0.2 == 0.3",
        "crypto.md5(\"a\")",
        "io.jwt.decode(\"a.b.c\")",
        "json.patch({}, [])",
        "regex.globs_match(\"a\", \"a\")",
        "http.send({\"method\": \"get\", \"url\": \"http://127.0.0.1:1/\"})",
    ] {
        println!("{q:60} -> {:?}", eval(q));
    }
}

/// F: is a missing builtin "undefined" (doc claim) or a hard error?
#[test]
fn zz_f_missing_builtin_in_rule() {
    let d = dir("f-missing-builtin");
    fs::write(
        d.join("p.rego"),
        "package t\nimport rego.v1\ndeny contains \"x\" if { crypto.md5(\"a\") == \"y\" }\nallow if { count(deny) == 0 }\n",
    )
    .unwrap();
    let disp = RegorusPolicyDispatcher::new();
    let b = d.display().to_string();
    for q in ["data.t.deny", "data.t.allow"] {
        println!(
            "{q} -> {:?}",
            disp.evaluate(&rego_invocation(
                q,
                Some(b.clone()),
                BTreeMap::new(),
                json!({})
            ))
        );
    }
}

/// D: lock-ordering / poisoning stress: cached engine built ON the worker
/// thread while callers time out and abandon workers.
#[test]
fn zz_d_cache_lock_stress() {
    let d = dir("d-lock-stress");
    for i in 0..80 {
        fs::write(
            d.join(format!("p{i}.rego")),
            format!("package p{i}\nimport rego.v1\nv := {i}\n"),
        )
        .unwrap();
    }
    fs::write(
        d.join("slow.rego"),
        "package slow\nimport rego.v1\nv := count(numbers.range(0, 40000000))\n",
    )
    .unwrap();
    let b = d.display().to_string();
    let disp = Arc::new(RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new()
            .with_policy_cache(true)
            .with_eval_timeout(Duration::from_millis(15)),
    ));
    let t = Instant::now();
    let hs: Vec<_> = (0..24)
        .map(|i| {
            let disp = Arc::clone(&disp);
            let b = b.clone();
            std::thread::spawn(move || {
                let q = if i % 2 == 0 {
                    "data.slow.v"
                } else {
                    "data.p0.v"
                };
                for _ in 0..40 {
                    let _ = disp.evaluate(&rego_invocation(
                        q,
                        Some(b.clone()),
                        BTreeMap::new(),
                        json!({}),
                    ));
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    println!("lock stress finished in {:?} (no deadlock)", t.elapsed());
    // cache must still work after all that churn
    let long = RegorusPolicyDispatcher::with_runner(
        RegorusRegoRunner::new()
            .with_policy_cache(true)
            .with_eval_timeout(Duration::from_secs(30)),
    );
    println!(
        "post-stress eval: {:?}",
        long.evaluate(&rego_invocation(
            "data.p0.v",
            Some(b),
            BTreeMap::new(),
            json!({})
        ))
    );
}
