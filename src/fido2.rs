use argon2::password_hash::rand_core::{OsRng, RngCore};
use ctap_hid_fido2::{
    FidoKeyHid, FidoKeyHidFactory,
    fidokey::{
        AssertionExtension, GetAssertionArgsBuilder, MakeCredentialArgsBuilder,
        credential_management::credential_management_params::CredentialProtectionPolicy,
    },
    public_key::{self, PublicKey},
    public_key_credential_user_entity::PublicKeyCredentialUserEntity,
    verifier,
};
use ctap_hid_fido2::fidokey::credential_management::credential_management_params::Rp;
use secrecy::{ExposeSecret, SecretSlice, SecretString};

pub fn ctap_register(pin: &SecretString) -> Result<(Vec<u8>, String, Vec<u8>), Box<dyn std::error::Error>> {
    let device = FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())?;
    // println!("{:}", device.get_info()?);
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
    const RP_ID: &str = "vaulty.app";
    let username = "Dennis";
    let args = MakeCredentialArgsBuilder::new(RP_ID, &buf)
        .user_entity(
            &(PublicKeyCredentialUserEntity::new(
                Some(username.as_bytes()),
                Some(username),
                Some(username),
            )),
        )
        .pin(pin.expose_secret())
        // .resident_key()
        .build();
    let attestation = device.make_credential_with_args(&args)?;
    // println!("{:}", attestation);
    let verify = verifier::verify_attestation(RP_ID, &buf, &attestation);
    // println!("{:}", verify.is_success);
    // println!("{:}", hex::encode(verify.credential_id));
    // let pub_key = verify.credential_public_key.clone();
    // PublicKey::with_der(&pub_key.der, public_key::PublicKeyType::Ecdsa256);
    // println!("{:}", hex::encode(verify.credential_public_key.der));
    if !verify.is_success { return Err("FIDO2 attestation verification failed".into()); }
    Ok((verify.credential_id, RP_ID.to_string(), verify.credential_public_key.der))
}

pub fn ctap_authenticate(kek: &[u8; 32],  pin: &SecretString, cred_id: Vec<Vec<u8>>, rp: &String, pub_key: Vec<Vec<u8>>) -> Result<([u8; 32], bool, Vec<u8>), Box<dyn std::error::Error>> {
    let device = FidoKeyHidFactory::create(&ctap_hid_fido2::Cfg::init())?;
    // print!("{:}", device.get_info()?);
    let mut buf = vec![0u8; 32];
    OsRng.fill_bytes(&mut buf);
    // let extension = AssertionExtension::create_hmac_secret_from_string("Test");
    let extension = AssertionExtension::HmacSecret(Some(*kek));


    let mut args = GetAssertionArgsBuilder::new(rp, &buf)
        .pin(pin.expose_secret())
        .extensions(&[extension])
        .build();
    args.credential_ids = cred_id.clone();
    // challenge
    // rpId
    // signature
    // (optionally) sign_count


    let assertion = device.get_assertion_with_args(&args)?;
    let assert = assertion.get(0).ok_or("Could not find assertion")?;
    let prf: [u8; 32] = assert
        .extensions
        .iter()
        .find_map(|e| match e {
            AssertionExtension::HmacSecret(Some(bytes)) => Some(*bytes),
            _ => None,
        }).ok_or("Could not find hmac secret in extensions")?;
    // println!("{:?}", prf);
    let idx = cred_id.iter().position(|e| e == &assert.credential_id).ok_or("Could not find credential id in list")?;

    // let verify = true;

    let verify = verifier::verify_assertion(
        rp,
        &(PublicKey::with_der(pub_key.get(idx).ok_or("Index out of bounds")?, public_key::PublicKeyType::Ecdsa256)),
        &buf,
        &(assert),
    );
    let credential_id = assert.credential_id.clone();
    if !verify { return Err("FIDO2 assertion verification failed".into()); }
    Ok((prf, verify, credential_id))
}