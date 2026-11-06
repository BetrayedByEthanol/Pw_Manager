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
    /// Strict, bounded reader for the legacy password payload.
    /// Full canonical schema/padding belongs to V02.
    pub fn deserialize(data: &Vec<u8>) -> Result<PasswordEntry, Box<dyn std::error::Error>> {
        fn bytes<'a>(data: &'a [u8], at: &mut usize, n: usize)
            -> Result<&'a [u8], Box<dyn std::error::Error>>
        {
            let end = at.checked_add(n).ok_or("payload length overflow")?;
            let value = data.get(*at..end).ok_or("truncated password payload")?;
            *at = end;
            Ok(value)
        }
        fn len(data: &[u8], at: &mut usize) -> Result<u16, Box<dyn std::error::Error>> {
            Ok(u16::from_le_bytes(bytes(data, at, 2)?.try_into()?))
        }
        fn field(data: &[u8], at: &mut usize)
            -> Result<(u16, String), Box<dyn std::error::Error>>
        {
            let n = len(data, at)?;
            let value = String::from_utf8(bytes(data, at, n as usize)?.to_vec())?;
            Ok((n, value))
        }
        let mut at = 0usize;
        let (title_length, title) = field(data, &mut at)?;
        let (username_length, username_raw) = field(data, &mut at)?;
        let username = (username_length != 0).then_some(username_raw);
        let (password_length, password_raw) = field(data, &mut at)?;
        let password = SecretString::from(password_raw);
        let url_count = len(data, &mut at)?;
        if url_count as usize > (data.len() - at) / 2 {
            return Err("invalid URL count".into());
        }
        let mut urls = Vec::with_capacity(url_count as usize);
        for _ in 0..url_count {
            let (_, url) = field(data, &mut at)?;
            urls.push(url);
        }
        let (notes_length, notes_raw) = field(data, &mut at)?;
        let notes = (notes_length != 0).then_some(notes_raw);
        if at != data.len() { return Err("unexpected trailing password payload data".into()); }
        Ok(Self {
            title_length, title, username_length, username, password_length,
            password, url_count, urls, notes_length, notes,
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

use std::fmt;

impl fmt::Display for PasswordEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Title   : {}", self.title)?;

        if let Some(username) = &self.username {
            writeln!(f, "Username: {}", username)?;
        }

        writeln!(f, "Password: [REDACTED]")?;

        if !self.urls.is_empty() {
            writeln!(f, "URLs    :")?;
            for url in &self.urls {
                writeln!(f, "  - {}", url)?;
            }
        }

        if let Some(notes) = &self.notes {
            writeln!(f, "Notes   : {}", notes)?;
        }

        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_legacy_password_payload_rejected_without_panicking() {
        let entry = PasswordEntry {
            title_length: 4, title: "test".into(),
            username_length: 4, username: Some("user".into()),
            password_length: 6, password: SecretString::from("secret".to_owned()),
            url_count: 1, urls: vec!["https://example.org".into()],
            notes_length: 4, notes: Some("note".into()),
        };
        let data = entry.serialize();
        let restored = PasswordEntry::deserialize(&data).unwrap();
        assert_eq!(restored.title, "test");
        assert_eq!(restored.username.as_deref(), Some("user"));
        assert_eq!(restored.urls.len(), 1);
        for len in 0..data.len() {
            assert!(PasswordEntry::deserialize(&data[..len].to_vec()).is_err());
        }
        let mut oversized = data.clone();
        oversized[0..2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(PasswordEntry::deserialize(&oversized).is_err());
        let mut trailing = data.clone();
        trailing.push(42);
        assert!(PasswordEntry::deserialize(&trailing).is_err());
    }
    #[test]
    fn password_display_is_redacted_by_default() {
        let entry = PasswordEntry {
            title_length: 0, title: String::new(),
            username_length: 0, username: None,
            password_length: 25, password: SecretString::from("SYNTHETIC_DISPLAY_TEST_KEY".to_owned()),
            url_count: 0, urls: Vec::new(),
            notes_length: 0, notes: None,
        };
        let shown = entry.to_string();
        assert!(shown.contains("[REDACTED]"));
        assert!(!shown.contains("SYNTHETIC_DISPLAY_TEST_KEY"));
    }
}
