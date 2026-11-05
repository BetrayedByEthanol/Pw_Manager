use std::{env,fs,process};
use vaulty_security_probes::{Policy,analyze,blast_radius,kek};
fn run()->Result<i32,String>{
    let args:Vec<String>=env::args().skip(1).collect();
    if args.len()==2 && args[0]=="--kek-vectors" {
        let data=fs::read_to_string(&args[1]).map_err(|e|e.to_string())?;
        let v=serde_json::from_str(&data).map_err(|e|format!("Invalid JSON: {e}"))?;
        let n=kek::verify(&v)?;
        println!("PASS: {n} KEK / commit-key vectors");return Ok(0);
    }
    let file=args.first().ok_or("Usage: vaulty-security-probes POLICY.json --entry ENTRY [--state loaded|cold] | --blast-radius | --kek-vectors JSON")?;
    let mut entry=None;let mut state="loaded";let mut blast=false;
    let mut i=1;
    while i<args.len(){
        match args[i].as_str(){
            "--entry" if i+1<args.len()=>{entry=Some(args[i+1].as_str());i+=2},
            "--state" if i+1<args.len()=>{state=args[i+1].as_str();i+=2},
            "--blast-radius"=>{blast=true;i+=1},
            other=>return Err(format!("Unexpected argument {other}")),
        }
    }
    let text=fs::read_to_string(file).map_err(|e|e.to_string())?;
    if text.len()>1_048_576{return Err("Policy JSON too large".into());}
    let p:Policy=serde_json::from_str(&text).map_err(|e|e.to_string())?;
    let output=if blast{blast_radius(&p,state)?}else{analyze(&p,entry.ok_or("--entry required")?,state)?};
    println!("{}",serde_json::to_string_pretty(&output).map_err(|e|e.to_string())?);
    let issues=output.get("issues").and_then(|v|v.as_array());
    Ok(if issues.is_some_and(|a|a.iter().any(|v|v.as_str()!=Some("NO_CURRENTLY_USABLE_COMPLETE_ROUTE"))){1}else{0})
}
fn main(){match run(){Ok(code)=>process::exit(code),Err(e)=>{eprintln!("error: {e}");process::exit(2)}}}
