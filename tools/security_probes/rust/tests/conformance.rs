use serde_json::{Value,json};
use std::{fs,path::PathBuf};
use vaulty_security_probes::{Policy,analyze,blast_radius,kek};

fn fixture(name:&str)->Value{
    let path=PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../fixtures").join(name);
    serde_json::from_str(&fs::read_to_string(&path).expect("read fixture")).expect("JSON fixture")
}
fn policy(name:&str)->Policy{serde_json::from_value(fixture(name)).unwrap()}
fn sorted_values(v:&Value)->Vec<Value>{
    let mut x=v.as_array().expect("expected array").clone();
    x.sort_by_key(|item|item.to_string());x
}

#[test]
fn same_json_policy_cases_as_python_reference(){
    let spec=fixture("conformance.json");
    assert_eq!(spec["version"],"vaulty-route-conformance-v1");
    for case in spec["cases"].as_array().unwrap(){
        let p=policy(case["file"].as_str().unwrap());
        let result=analyze(&p,case["entry"].as_str().unwrap(),case["state"].as_str().unwrap()).unwrap();
        assert_eq!(result["issues"],case["issues"],"issues: {}",case["id"]);
        for field in ["isolation_tier", "normal_provider", "fresh_physical_operation_required_per_normal_read"] {
            if case.get(field).is_some() {
                assert_eq!(result[field],case[field],"{field}: {}",case["id"]);
            }
        }
        assert_eq!(result["entry_hardware_mandatory_on_all_paths"],case["entry_hardware_mandatory_on_all_paths"],"hardware: {}",case["id"]);
        assert_eq!(result["hardware_bypass_routes"].as_array().unwrap().len(),case["hardware_bypass_count"].as_u64().unwrap() as usize,"bypass {}",case["id"]);
        let cnt=result["configured_routes"].as_array().unwrap().iter().filter(|r|r["entry_recovery"]==true).count();
        assert_eq!(cnt,case["entry_recovery_count"].as_u64().unwrap() as usize,"recovery {}",case["id"]);
        let weakest=Value::Array(result["weakest_configured"].as_array().unwrap().iter().map(|r|r["factors"].clone()).collect());
        assert_eq!(sorted_values(&weakest),sorted_values(&case["weakest_factor_sets"]),"weakest {}",case["id"]);
    }
}

#[test]
fn shared_blast_radius_fixture_matches_python(){
    let p=policy("routes.json");
    let expected=fixture("conformance.json");
    let got=blast_radius(&p,"loaded").unwrap();
    let m=got["by_material"].as_object().unwrap();
    for (id,properties) in expected["loaded_blast_radius"].as_object().unwrap(){
        let output=m.get(id).expect("material exists");
        assert_eq!(output["dependent_entries"],properties["dependent_entries"],"{id}");
        assert_eq!(output["exposed_without_other_factors"],properties["exposed_without_other_factors"],"{id}");
        assert_eq!(output["remaining_factor_sets"],properties["remaining_factor_sets"],"{id}");
    }
    assert_eq!(m.len(),expected["loaded_blast_radius"].as_object().unwrap().len());
    assert!(m.get("key:VMK").is_none());
}

#[test]
fn rejects_missing_external_references_and_cycles(){
    let mut v=fixture("routes.json");
    v["keys"]["DEK-independent"]["slots"][0]["requires"]=json!(["factor:missing"]);
    let p:Policy=serde_json::from_value(v).unwrap();
    assert!(analyze(&p,"independent","loaded").unwrap_err().contains("Unresolved"));
    let mut v=fixture("routes.json");
    v["keys"]["VERS"]["slots"][0]["requires"]=json!(["key:DEK-ordinary"]);
    let p:Policy=serde_json::from_value(v).unwrap();
    assert!(analyze(&p,"ordinary","loaded").unwrap_err().contains("Cycle"));
}

#[test]
fn enforces_independent_code_ownership(){
    let mut v=fixture("routes.json");
    v["factors"]["ind_code"]["entry_id"]=json!("strict");
    let p:Policy=serde_json::from_value(v).unwrap();
    let out=analyze(&p,"independent","loaded").unwrap();
    assert!(out["issues"].as_array().unwrap().contains(&json!("ENTRY_CODE_SCOPE_MISMATCH")));
    assert!(out["issues"].as_array().unwrap().contains(&json!("INDEPENDENT_RECOVERY_SCOPE_BYPASS")));
}

#[test]
fn nine_kek_commitment_vectors_match_python_reference(){
    let vectors=fixture("kek_vectors.json");
    assert_eq!(kek::verify(&vectors).unwrap(),9);
    for v in vectors["vectors"].as_array().unwrap(){
        let mut changed=v.clone();
        changed["slot_id"]=json!(format!("{}-mutated",v["slot_id"].as_str().unwrap()));
        assert_ne!(kek::derive(v).unwrap()["kek_hex"],kek::derive(&changed).unwrap()["kek_hex"]);
        assert_ne!(kek::derive(v).unwrap()["commit_tag_hex"],kek::derive(&changed).unwrap()["commit_tag_hex"]);
    }
}

#[test]
fn key_commitment_binds_nonce_aad_and_ciphertext(){
    let vectors=fixture("kek_vectors.json");
    let v=&vectors["vectors"][0];
    let expected=kek::derive(v).unwrap()["commit_tag_hex"].clone();
    for field in ["nonce_hex","aad_hex","ciphertext_hex"]{
        let mut other=v.clone();
        let original=other[field].as_str().unwrap();
        other[field]=json!(format!("ff{}",&original[2..]));
        assert_ne!(expected,kek::derive(&other).unwrap()["commit_tag_hex"],"{field}");
    }
}

#[test]
fn s1_entry_selector_requires_physical_or_resident_virtual_as_configured(){
    let p=policy("routes.json");
    let virtual_report=analyze(&p,"ordinary","loaded").unwrap();
    assert_eq!(virtual_report["normal_provider"],"virtual_prf");
    assert_eq!(virtual_report["fresh_physical_operation_required_per_normal_read"],false);
    let physical_report=analyze(&p,"strict","loaded").unwrap();
    assert_eq!(physical_report["normal_provider"],"physical_fido2");
    assert_eq!(physical_report["fresh_physical_operation_required_per_normal_read"],true);
    let mut absent=p.clone();
    absent.factors.get_mut("yubikey").unwrap().available=false;
    let unavailable=analyze(&absent,"strict","loaded").unwrap();
    assert!(unavailable["usable_routes"].as_array().unwrap().is_empty());
}

#[test]
fn s2_isolated_requires_physical_even_on_independent_recovery(){
    let valid=policy("owner_isolated-independent-hardware-loaded.json");
    let a=analyze(&valid,"independent","loaded").unwrap();
    assert_eq!(a["issues"],json!([]));
    let bypass=policy("owner_isolated-independent-code-only.json");
    let a=analyze(&bypass,"independent","loaded").unwrap();
    assert!(a["issues"].as_array().unwrap().contains(&json!("ISOLATED_HAS_NON_HARDWARE_ACCESS_ROUTE")));
    let mut invalid=fixture("routes.json");
    invalid["entries"][0]["isolation_tier"]=json!("ISOLATED");
    let invalid:Policy=serde_json::from_value(invalid).unwrap();
    assert!(analyze(&invalid,"ordinary","loaded").unwrap_err().contains("Isolated entry"));
}
