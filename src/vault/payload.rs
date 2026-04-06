use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PasswordEntry {
    pub title: String,
    pub username: Option<String>,
    pub password: String,
    pub urls: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PasskeyEntry {
    pub title: String,
    pub rp_id: String,
    pub credential_id: Vec<u8>,
    pub user_handle: Vec<u8>,
    pub public_key: Vec<u8>,
    pub private_key_encrypted: Vec<u8>,
    pub sign_count: u32,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SecureNoteEntry {
    pub title: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct CardEntry {
    pub title: String,
    pub cardholder_name: String,
    pub number: String,
    pub expiry_month: u8,
    pub expiry_year: u16,
    pub cvv: Option<String>,
    pub notes: Option<String>,
}