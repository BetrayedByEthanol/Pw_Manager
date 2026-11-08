//! Offline regression tests only; never call fido2-cred/fido2-assert.
use super::*;

fn sample() -> String {
    let mut rows=BTreeMap::new();
    for (k,v) in [
        ("schema","\"vaulty-v02j-observation-v1\""),
        ("review_only","true"),("device_execution","\"OBSERVED\""),
        ("full_i_p01_to_i_p09_matrix","\"NOT_EXECUTED\""),
        ("operation","\"signed_native_ctap_test_assertions\""),
        ("signature_and_requested_flags_checked","true"),
        ("assurance_requested","\"uv\""),
        ("uv_absence_verified","false"),
        ("repeat_prf_stable","true"),
        ("different_entry_prf_distinct","true"),
        ("entry_route_ready","false"),
        ("open_15_approved","false"),
        ("open_01_approved","false"),
    ] {rows.insert(k,v);}
    let mut out=String::from("{\n");
    for (i,(k,v)) in rows.iter().enumerate() {
        out.push_str(&format!("  \"{k}\": {v}{}\n",
                              if i+1==rows.len(){""}else{","}));
    }
    out.push_str("}\n");
    out
}

#[test]
fn canonical_python_receipt_parses_without_accepting_secrets() {
    assert_eq!(observation(&sample()).unwrap(),
               Observation{stable:true,isolated:true});
}
#[test]
fn rejects_claimed_approval_or_unauthenticated_results() {
    let input=sample();
    for (a,b) in [
        ("\"open_15_approved\": false","\"open_15_approved\": true"),
        ("\"open_01_approved\": false","\"open_01_approved\": true"),
        ("\"entry_route_ready\": false","\"entry_route_ready\": true"),
        ("\"review_only\": true","\"review_only\": false"),
        ("\"assurance_requested\": \"uv\"","\"assurance_requested\": \"touch-only\""),
        ("\"signature_and_requested_flags_checked\": true",
         "\"signature_and_requested_flags_checked\": false"),
        ("\"different_entry_prf_distinct\": true","\"different_entry_prf_distinct\": null"),
    ] {
        assert!(observation(&input.replace(a,b)).is_err());
    }
}
#[test]
fn unknown_dup_trailing_and_oversize_receipts_rejected() {
    let input=sample();
    let malicious=[
        input.replace("  \"review_only\": true,",
                      "  \"review_only\": true,\n  \"review_only\": true,"),
        input.replace("  \"review_only\": true,",
                      "  \"credential_id\": \"SECRET\",\n  \"review_only\": true,"),
        format!("{input}{{}}"),
        String::from("not JSON"),
        "{}".into(),
        " ".repeat(4097),
    ];
    for row in malicious {assert!(observation(&row).is_err());}
}
#[test]
fn negative_prf_observation_is_flagged_not_upgraded_to_pass() {
    let input=sample().replace("\"repeat_prf_stable\": true",
                               "\"repeat_prf_stable\": false");
    let x=observation(&input).unwrap();
    assert_eq!(observed(&Some(x)),"OBSERVED_MISMATCH");
}
#[test]
fn report_is_redacted_and_cannot_mark_open_15_or_matrix_complete() {
    let sha="1".repeat(40);
    let good=Some(Observation{stable:true,isolated:true});
    let result=report(&sha,"LOCAL_OBSERVATIONS_CAPTURED",&good,&good);
    for i in 1..=9 {assert!(result.contains(&format!("\"I-P{i:02}\"")));}
    assert!(result.contains("\"full_i_p01_to_i_p09_matrix\": \"NOT_COMPLETE\""));
    assert!(result.contains("\"I-P05\": \"NOT_EXECUTED\""));
    assert!(result.contains("\"open_15\": \"BLOCKED\""));
    assert!(result.contains("\"open_01\": \"BLOCKED\""));
    assert!(result.contains("\"entry_route_ready\": false"));
    assert!(!result.contains("\"PASS\""));
    assert!(!result.contains("/dev/hidraw"));
    assert!(!result.contains("credential_id"));
    assert!(!result.contains("PRF_VALUE"));
}
#[test]
fn failed_or_interrupted_session_never_claims_finished_tests() {
    let s=report(&"f".repeat(40),"INCOMPLETE",
                 &Some(Observation{stable:true,isolated:true}),&None);
    assert!(s.contains("\"backup\": \"NOT_EXECUTED\""));
    assert!(s.contains("\"I-P01\": \"NOT_EXECUTED\""));
    assert!(s.contains("\"open_15\": \"BLOCKED\""));
}
#[test]
fn hardware_flag_explicit_and_both_roles_required() {
    assert!(options(["run".to_owned()].into_iter()).is_err());
    assert!(options(["run","--hardware-test"].into_iter().map(str::to_owned)).is_err());
    let ok=options(["run","--hardware-test","--primary-device","/dev/hidraw0",
                    "--backup-device","/dev/hidraw1","--rp-id",
                    "vaulty-review.localhost"].into_iter().map(str::to_owned)).unwrap();
    assert!(ok.live);
    assert_eq!(ok.rp,"vaulty-review.localhost");
    assert!(options(["run","--hardware-test","--hardware-test",
                     "--primary-device","/dev/hidraw0",
                     "--backup-device","/dev/hidraw1"].into_iter().map(str::to_owned)).is_err());
}
#[test]
fn cannot_inject_shell_commands_or_wrong_hid_device() {
    for s in ["/dev/null","/tmp/hidraw1","/dev/hidraw1;echo bad",
              "../dev/hidraw1","/dev/hidraw","/dev/hidraw1/../../root"] {
        assert!(device(s).is_err());
    }
}
#[test]
fn no_production_rp_defaults_and_invalid_rps_fail() {
    assert_eq!(options(["preflight".to_owned()].into_iter()).unwrap().rp,
               "vaulty-review.localhost");
    for s in ["", "x", "hello", "BAD.COM","a..b","-a.test","a.test-",
              "a.test\nnew", "a.test;foo"] {
        assert!(!valid_rp(s));
    }
}

#[test]
fn rejects_noncanonical_comma_whitespace_order_and_newline() {
    let input=sample();
    assert!(observation(&input.replace(",\n", "\n")).is_err());
    let with_trailing_comma=input.replacen("\n}\n", ",\n}\n", 1);
    assert!(observation(&with_trailing_comma).is_err());
    assert!(observation(&input.replace("  \"review_only\":", "    \"review_only\":")).is_err());
    assert!(observation(input.trim_end_matches('\n')).is_err());
    let lines:Vec<_>=input.lines().collect();
    let mut scrambled=lines.clone();
    scrambled.swap(1,2);
    assert!(observation(&(scrambled.join("\n")+"\n")).is_err());
}

#[test]
fn redacted_report_is_atomic_and_precreated_incomplete() {
    let dir=std::env::temp_dir().join(format!(
        "v02k-ci-test-{}-{}",std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
    std::fs::create_dir(&dir).unwrap();
    let empty=report(&"a".repeat(40),"INCOMPLETE",&None,&None);
    let path=store_report(&dir,&empty).unwrap();
    assert!(path.is_file());
    assert_eq!(std::fs::read_to_string(&path).unwrap(),empty);
    let primary=Some(Observation { stable:true, isolated:true });
    let partial=report(&"a".repeat(40),"INCOMPLETE",&primary,&None);
    store_report(&dir,&partial).unwrap();
    let recorded=std::fs::read_to_string(&path).unwrap();
    assert!(recorded.contains("\"backup\": \"NOT_EXECUTED\""));
    assert!(recorded.contains("\"primary\": \"OBSERVED\""));
    assert!(recorded.contains("\"open_15\": \"BLOCKED\""));
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
