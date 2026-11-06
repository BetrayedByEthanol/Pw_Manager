//! Reference-only implementation of OPEN-18 and OPEN-01 candidate transcripts.
//! Inputs are an *authenticated* policy snapshot; never authorize operations
//! using an untrusted file or browser-supplied policy document.
pub mod kek;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ROUTES: usize = 4096;
fn active() -> String { "active".into() }
fn available() -> bool { true }
fn states() -> Vec<String> { vec!["loaded".into(), "cold".into()] }

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Policy {
    pub schema: String,
    pub factors: BTreeMap<String, Factor>,
    pub keys: BTreeMap<String, Key>,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Factor {
    pub kind: String,
    #[serde(default = "active")]
    pub status: String,
    #[serde(default = "available")]
    pub available: bool,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub entry_id: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Key { pub slots: Vec<Slot> }
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Slot {
    pub id: String,
    pub kind: String,
    pub requires: Vec<String>,
    #[serde(default = "active")]
    pub status: String,
    #[serde(default = "states")]
    pub states: Vec<String>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Entry {
    pub id: String,
    pub dek: String,
    pub policy: String,
    pub recovery_policy: String,
    #[serde(default)]
    pub first_key: Option<String>,
    #[serde(default)]
    pub entry_password_factor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
struct Route {
    factors: BTreeSet<String>,
    keys: BTreeSet<String>,
    slots: BTreeSet<String>,
    recovery_slots: BTreeSet<String>,
    entry_recovery: bool,
    outer_recovery: bool,
    used_compromise: bool,
}
impl Route {
    fn and(&self, other: &Self) -> Self {
        Self {
            factors: self.factors.union(&other.factors).cloned().collect(),
            keys: self.keys.union(&other.keys).cloned().collect(),
            slots: self.slots.union(&other.slots).cloned().collect(),
            recovery_slots: self.recovery_slots.union(&other.recovery_slots).cloned().collect(),
            entry_recovery: self.entry_recovery || other.entry_recovery,
            outer_recovery: self.outer_recovery || other.outer_recovery,
            used_compromise: self.used_compromise || other.used_compromise,
        }
    }
}

fn is_status(s: &str) -> bool { matches!(s,"active"|"revoked"|"suspended"|"disabled") }
fn is_kind(s: &str) -> bool { matches!(s,"master_password"|"entry_password"|"physical_fido2"|"virtual_prf"|"recovery_code"|"loaded_session") }
fn is_policy(s: &str) -> bool { matches!(s,"ENTRY_DEFAULT_VIRTUAL"|"ENTRY_DEFAULT_PHYSICAL"|"ENTRY_PASSWORD_VIRTUAL"|"ENTRY_PASSWORD_PHYSICAL") }
fn is_recovery_policy(s: &str) -> bool { matches!(s,"SHARED"|"GROUP"|"INDEPENDENT"|"STRICT_NONE") }

pub fn validate(p: &Policy) -> Result<(), String> {
    if p.schema != "vaulty-route-v1" { return Err("Unsupported route-graph schema".into()); }
    if p.factors.len()>256 || p.keys.len()>256 || p.entries.len()>256 {
        return Err("Graph exceeds bounded limits".into());
    }
    for (id, f) in &p.factors {
        if id.is_empty() || !is_kind(&f.kind) || !is_status(&f.status) {
            return Err(format!("Invalid factor {id}"));
        }
    }
    let mut slots = BTreeSet::new();
    for (kid, k) in &p.keys {
        if kid.is_empty() || k.slots.len()>32 { return Err(format!("Invalid key {kid}")); }
        for slot in &k.slots {
            if slot.id.is_empty() || !slots.insert(slot.id.clone()) {
                return Err(format!("Duplicate/empty slot id {}",slot.id));
            }
            if !matches!(slot.kind.as_str(),"normal"|"recovery"|"resident") || !is_status(&slot.status) ||
                slot.states.is_empty() || slot.states.iter().any(|s| !matches!(s.as_str(),"cold"|"loaded")) ||
                (slot.kind=="resident" && slot.states.iter().any(|s| s=="cold")) ||
                slot.requires.is_empty() || slot.requires.len()>16 {
                return Err(format!("Invalid slot {}", slot.id));
            }
            for rf in &slot.requires {
                match rf.split_once(':') {
                    Some(("factor", name)) if p.factors.contains_key(name) => (),
                    Some(("key", name)) if p.keys.contains_key(name) => (),
                    _ => return Err(format!("Unresolved requirement {rf} in {}",slot.id)),
                }
            }
        }
    }
    if !p.keys.contains_key("VMK") { return Err("Missing VMK".into()); }
    let mut entry_ids = BTreeSet::new();
    for e in &p.entries {
        if e.id.is_empty() || !entry_ids.insert(e.id.clone()) || !p.keys.contains_key(&e.dek) ||
            !is_policy(&e.policy) || !is_recovery_policy(&e.recovery_policy) {
            return Err(format!("Invalid entry {}",e.id));
        }
        if e.policy.starts_with("ENTRY_DEFAULT_") && !e.first_key.as_ref().is_some_and(|k|p.keys.contains_key(k)) {
            return Err(format!("Missing first root for {}",e.id));
        }
        if e.policy.starts_with("ENTRY_PASSWORD_") && !e.entry_password_factor.as_ref()
            .and_then(|id|p.factors.get(id)).is_some_and(|f|f.kind=="entry_password") {
            return Err(format!("Missing entry password for {}",e.id));
        }
    }
    for (id, f) in &p.factors {
        if f.kind=="recovery_code" {
            let scope=f.scope.as_deref().unwrap_or("vault");
            match scope {
                "vault"=>(),
                "entry" if f.entry_id.as_ref().is_some_and(|id|entry_ids.contains(id))=>(),
                "group" if f.group_id.as_ref().is_some_and(|id|!id.is_empty())=>(),
                _=>return Err(format!("Invalid recovery code scope for {id}")),
            }
        }
    }
    Ok(())
}

fn routes_for_key(p:&Policy, kid:&str, state:&str, available_only:bool,
                  cache:&mut BTreeMap<String,Vec<Route>>, stack:&mut Vec<String>,
                  compromised:Option<&str>) -> Result<Vec<Route>,String> {
    if compromised.is_some_and(|id|id==format!("key:{kid}")) {
        let mut route=Route {used_compromise:true,..Default::default()};
        route.keys.insert(kid.into());
        return Ok(vec![route]);
    }
    if stack.iter().any(|s|s==kid) {
        return Err(format!("Cycle in key prerequisites: {} -> {kid}",stack.join(" -> ")));
    }
    if let Some(x)=cache.get(kid){return Ok(x.clone());}
    stack.push(kid.into());
    let mut result=BTreeSet::new();
    let key=&p.keys[kid];
    for slot in &key.slots {
        if slot.status!="active" || !slot.states.iter().any(|s|s==state) {continue;}
        let mut start=Route::default();
        start.keys.insert(kid.into());
        start.slots.insert(slot.id.clone());
        if slot.kind=="recovery"{start.recovery_slots.insert(slot.id.clone());}
        let mut choices=vec![start];
        for rf in &slot.requires {
            let (kind,name)=rf.split_once(':').ok_or_else(||format!("Invalid reference {rf}"))?;
            let options=if kind=="factor" {
                if compromised==Some(rf.as_str()) {
                    vec![Route{used_compromise:true,..Default::default()}]
                }else{
                    let f=&p.factors[name];
                    if f.status!="active" || available_only && !f.available{vec![]}
                    else {
                        let mut v=Route::default();v.factors.insert(name.into());vec![v]
                    }
                }
            }else{
                routes_for_key(p,name,state,available_only,cache,stack,compromised)?
            };
            if choices.len().checked_mul(options.len()).unwrap_or(usize::MAX)>MAX_ROUTES {
                return Err("Route expansion exceeds limit".into());
            }
            choices=choices.iter().flat_map(|a|options.iter().map(move |b|a.and(b))).collect();
            if choices.is_empty(){break;}
        }
        result.extend(choices);
        if result.len()>MAX_ROUTES {return Err("Route expansion exceeds limit".into());}
    }
    stack.pop();
    let got:Vec<_>=result.into_iter().collect();
    cache.insert(kid.into(),got.clone());
    Ok(got)
}
fn root_routes(p:&Policy,kid:&str,state:&str,available:bool,compromised:Option<&str>) -> Result<Vec<Route>,String>{
    routes_for_key(p,kid,state,available,&mut BTreeMap::new(),&mut vec![],compromised)
}
fn is_recovery(p:&Policy,r:&Route) -> bool {
    !r.recovery_slots.is_empty() || r.factors.iter().any(|id|p.factors[id].kind=="recovery_code")
}
fn has_hardware(p:&Policy,r:&Route)->bool{r.factors.iter().any(|id|p.factors[id].kind=="physical_fido2")}
fn independent_factors(p:&Policy,r:&Route)->Vec<String>{
    r.factors.iter().filter(|id|matches!(p.factors[*id].kind.as_str(),"master_password"|"entry_password"|"physical_fido2"|"recovery_code")).cloned().collect()
}
fn serialize(p:&Policy,r:&Route) -> Value {
    let kinds:BTreeSet<_>=r.factors.iter().map(|id|p.factors[id].kind.clone()).collect();
    let ind=independent_factors(p,r);
    json!({"factors":r.factors,"factor_kinds":kinds,"keys":r.keys,"slots":r.slots,
           "recovery_slots":r.recovery_slots,"recovery":is_recovery(p,r),
           "entry_recovery":r.entry_recovery,"outer_recovery":r.outer_recovery,
           "requires_physical":has_hardware(p,r),"independent_factors":ind,
           "independent_factor_count":ind.len()})
}
fn serialized(p:&Policy,rr:&[Route])->Vec<Value>{rr.iter().map(|r|serialize(p,r)).collect()}
fn minimal<'a>(routes:&'a [Route])->Vec<&'a Route> {
    routes.iter().filter(|r|!routes.iter().any(|o|o.factors.is_subset(&r.factors)&&o.factors!=r.factors)).collect()
}
fn weakest<'a>(p:&Policy,routes:&'a [Route])->Vec<&'a Route>{
    let rank=|r:&Route|(usize::from(has_hardware(p,r)),independent_factors(p,r).len());
    let Some(min)=routes.iter().map(rank).min() else{return vec![];};
    routes.iter().filter(|r|rank(r)==min).collect()
}
fn sorted(routes:Vec<Route>)->Vec<Route>{routes.into_iter().collect::<BTreeSet<_>>().into_iter().collect()}
fn entry_routes(p:&Policy,e:&Entry,state:&str,available:bool) -> Result<(Vec<Route>,Vec<Route>),String> {
    let dek:Vec<_>=root_routes(p,&e.dek,state,available,None)?.into_iter().map(|mut r|{
        r.entry_recovery=is_recovery(p,&r);r
    }).collect();
    if state=="loaded" {return Ok((dek.clone(),dek));}
    let vmk:Vec<_>=root_routes(p,"VMK",state,available,None)?.into_iter().map(|mut r|{
        r.outer_recovery=is_recovery(p,&r);r
    }).collect();
    if dek.len().checked_mul(vmk.len()).unwrap_or(usize::MAX)>MAX_ROUTES {
        return Err("Cold-open route expansion exceeds limit".into());
    }
    let all=sorted(dek.iter().flat_map(|d|vmk.iter().map(move |v|d.and(v))).collect());
    Ok((dek,all))
}

pub fn analyze(p:&Policy,entry_id:&str,state:&str)->Result<Value,String>{
    validate(p)?;
    if !matches!(state,"cold"|"loaded"){return Err("Invalid state".into());}
    let e=p.entries.iter().find(|e|e.id==entry_id).ok_or_else(||format!("Unknown entry {entry_id}"))?;
    let (dek,full)=entry_routes(p,e,state,false)?;
    let (_,usable)=entry_routes(p,e,state,true)?;
    let mut issues=BTreeSet::new();
    if full.is_empty(){issues.insert("NO_CONFIGURED_COMPLETE_ROUTE");}
    if usable.is_empty(){issues.insert("NO_CURRENTLY_USABLE_COMPLETE_ROUTE");}
    if dek.iter().any(|r|r.keys.contains("VMK")){issues.insert("ENTRY_KEK_DEPENDS_ON_VMK");}
    let strict_bypass:Vec<Route>=dek.iter().filter(|r|r.entry_recovery).cloned().collect();
    if e.recovery_policy=="STRICT_NONE" && !strict_bypass.is_empty(){
        issues.insert("STRICT_NONE_HAS_COMPLETE_RECOVERY_PATH");
    }
    if dek.iter().any(|r|r.factors.iter().any(|fid| {
        let f=&p.factors[fid];
        f.kind=="recovery_code" && f.scope.as_deref()==Some("entry") && f.entry_id.as_deref()!=Some(entry_id)
    })){issues.insert("ENTRY_CODE_SCOPE_MISMATCH");}
    if e.recovery_policy=="INDEPENDENT" {
        let slots=&p.keys[&e.dek].slots;
        let direct:BTreeSet<_>=slots.iter().filter(|s|s.kind=="recovery" && s.status=="active" && s.states.iter().any(|x|x==state)).map(|s|s.id.clone()).collect();
        let invalid=strict_bypass.iter().any(|r|{
            let owned:BTreeSet<_>=r.factors.iter().filter(|fid|{
                let f=&p.factors[*fid];
                f.kind=="recovery_code" && f.scope.as_deref()==Some("entry") && f.entry_id.as_deref()==Some(entry_id)
            }).cloned().collect();
            let direct_ok=slots.iter().any(|s|r.recovery_slots.contains(&s.id) && direct.contains(&s.id) &&
                s.requires.iter().all(|rf|rf.starts_with("factor:")) &&
                s.requires.iter().any(|rf|owned.iter().any(|id|rf==&format!("factor:{id}"))));
            owned.is_empty() || !direct_ok || r.factors.iter().any(|fid|{
                let f=&p.factors[fid];f.kind=="recovery_code" && !owned.contains(fid)
            }) || r.recovery_slots.iter().any(|id|!direct.contains(id))
        });
        if strict_bypass.is_empty(){issues.insert("INDEPENDENT_MISSING_ENTRY_RECOVERY");}
        else if invalid{issues.insert("INDEPENDENT_RECOVERY_SCOPE_BYPASS");}
    }
    let normal:Vec<_>=dek.iter().filter(|r|!r.entry_recovery).collect();
    if normal.is_empty(){issues.insert("NO_NORMAL_ENTRY_ROUTE");}
    let req_hw=e.policy.ends_with("_PHYSICAL");
    let req_default=e.policy.starts_with("ENTRY_DEFAULT_");
    for r in normal {
        if req_default && !e.first_key.as_ref().is_some_and(|key|r.keys.contains(key)) {
            issues.insert("NORMAL_ROUTE_MISSING_VERS_ROOT");
        }
        if !req_default && !e.entry_password_factor.as_ref().is_some_and(|id|r.factors.contains(id)){
            issues.insert("NORMAL_ROUTE_MISSING_ENTRY_PASSWORD");
        }
        if req_hw && !has_hardware(p,r){issues.insert("NORMAL_ROUTE_MISSING_PHYSICAL_PRF");}
        if !req_hw && !r.factors.iter().any(|fid|p.factors[fid].kind=="virtual_prf"){
            issues.insert("NORMAL_ROUTE_MISSING_VIRTUAL_PRF");
        }
    }
    let hardware_mandatory=!dek.is_empty() && dek.iter().all(|r|has_hardware(p,r));
    let bypass:Vec<_>=dek.iter().filter(|r|req_hw && !has_hardware(p,r)).cloned().collect();
    let strict=if e.recovery_policy=="STRICT_NONE"{serialized(p,&strict_bypass)}else{vec![]};
    Ok(json!({"entry":entry_id,"state":state,
        "configured_routes":serialized(p,&full),"usable_routes":serialized(p,&usable),
        "minimal_configured":minimal(&full).iter().map(|r|serialize(p,r)).collect::<Vec<_>>(),
        "minimal_usable":minimal(&usable).iter().map(|r|serialize(p,r)).collect::<Vec<_>>(),
        "weakest_configured":weakest(p,&full).iter().map(|r|serialize(p,r)).collect::<Vec<_>>(),
        "weakest_usable":weakest(p,&usable).iter().map(|r|serialize(p,r)).collect::<Vec<_>>(),
        "entry_hardware_mandatory_on_all_paths":hardware_mandatory,
        "hardware_bypass_routes":serialized(p,&bypass),
        "strict_entry_recovery_bypass_routes":strict,
        "issues":issues}))
}

/// Configured downstream fanout and residual factors after one material compromise.
/// Does not equate an exported slot-scoped PRF output with full device compromise.
pub fn blast_radius(p:&Policy,state:&str)->Result<Value,String>{
    validate(p)?;
    if !matches!(state,"cold"|"loaded"){return Err("Invalid state".into());}
    let mut base=BTreeMap::new();
    for e in &p.entries{base.insert(e.id.clone(),root_routes(p,&e.dek,state,false,None)?);}
    let materials:Vec<_>=p.factors.keys().map(|id|format!("factor:{id}"))
        .chain(p.keys.keys().map(|id|format!("key:{id}"))).collect();
    let mut by_material=BTreeMap::new();
    for material in materials {
        let (typ,name)=material.split_once(':').ok_or("Invalid material")?;
        let (mut impacted, mut exposed)=(Vec::new(),Vec::new());
        let mut residual=BTreeMap::new();
        for e in &p.entries {
            let relevant=base[&e.id].iter().any(|r|if typ=="factor"{r.factors.contains(name)}else{r.keys.contains(name)})
                || typ=="key" && name==e.dek;
            if !relevant {continue;}
            impacted.push(e.id.clone());
            let routes:Vec<_>=root_routes(p,&e.dek,state,false,Some(&material))?
                .into_iter().filter(|r|r.used_compromise).collect();
            let minimal_sets:BTreeSet<Vec<String>>=minimal(&routes).iter().map(|r|r.factors.iter().cloned().collect()).collect();
            if minimal_sets.contains(&vec![]){exposed.push(e.id.clone());}
            residual.insert(e.id.clone(),minimal_sets);
        }
        if !impacted.is_empty(){
            impacted.sort();exposed.sort();
            by_material.insert(material,json!({"dependent_entries":impacted,"dependent_count":impacted.len(),
                "exposed_without_other_factors":exposed,"exposed_count":exposed.len(),
                "remaining_factor_sets":residual}));
        }
    }
    Ok(json!({"state":state,"entry_count":p.entries.len(),"by_material":by_material}))
}
