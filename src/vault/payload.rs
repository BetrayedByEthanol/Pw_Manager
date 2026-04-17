use std::any::Any;
use aes_gcm::aead::Buffer;
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct PasswordEntry {
    pub title_length: u16,
    pub title: String,
    pub username_length: u16,
    pub username: Option<String>,
    pub password_length: u16,
    pub password: SecretString,
    pub url_count: u16,
    pub urls: Vec<String>,
    pub notes_length: u16,
    pub notes: Option<String>,
}

impl PasswordEntry {
    pub fn deserialize(data: &Vec<u8>) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        let mut idx : usize = 0;
        let title_length: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
        idx += 2;
        let title = String::from_utf8(data[idx..idx+title_length as usize].to_vec())?;
        idx += title_length as usize;
        let username_length: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
        idx += 2;
        let username = if username_length > 0 {
            Some(String::from_utf8(data[idx..idx+username_length as usize].to_vec())?)
        } else {
            None
        };
        idx += username_length as usize;
        let password_length: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
        idx += 2;
        let password = SecretString::from(String::from_utf8(data[idx..idx+password_length as usize].to_vec())?);
        idx += password_length as usize;
        let url_count: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
        idx += 2;
        let mut urls: Vec<String> = vec![];
        for _ in 0..url_count {
            let url_length: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
            idx += 2;
            let url = String::from_utf8(data[idx..idx+url_length as usize].to_vec())?;
            idx += url_length as usize;
            urls.push(url);
        }
        let notes_length: u16 = u16::from_le_bytes([data[idx], data[idx+1]]);
        idx += 2;

        let notes = if notes_length > 0 {
            Some(String::from_utf8(data[idx..idx+notes_length as usize].to_vec())?)
        } else {
            None
        };
        idx += notes_length as usize;

        Ok(Self {
            title_length,
            title,
            username_length,
            username,
            password_length,
            password,
            url_count,
            urls,
            notes_length,
            notes,
        })
    }
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

pub trait TypeEntry: Any {
    fn as_any(&self) -> &dyn Any;
    fn serialize(&self) -> Vec<u8>;
    // fn deserialize(data: &Vec<u8>) -> &dyn Any;
}

impl TypeEntry for PasswordEntry {
    fn as_any(&self) -> &dyn Any { self }

    fn serialize(&self) -> Vec<u8> {
        let mut data: Vec<u8> = vec![];
        data.extend_from_slice(&self.title_length.to_le_bytes());
        data.extend_from_slice(self.title.as_bytes());
        data.extend_from_slice(&self.username_length.to_le_bytes());
        if let Some(username) = &self.username {
            data.extend_from_slice(username.as_bytes());
        }
        data.extend_from_slice(&self.password_length.to_le_bytes());
        data.extend_from_slice(self.password.expose_secret().as_bytes());
        data.extend_from_slice(&self.url_count.to_le_bytes());
        for url in &self.urls {
            let url_bytes = url.as_bytes();
            let url_length: u16 = url_bytes.len() as u16;

            data.extend_from_slice(&url_length.to_le_bytes());
            data.extend_from_slice(url_bytes);
        }
        data.extend_from_slice(&self.notes_length.to_le_bytes());
        if let Some(notes) = &self.notes {
            data.extend_from_slice(notes.as_bytes());
        }
        return data;
    }


}

