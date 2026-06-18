//! Persistent data model: applications, users, signing key, and the on-disk store.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::path::Path;

use crate::crypto;

fn default_port() -> u16 {
    4444
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningKey {
    pub kid: String,
    pub private_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Application {
    pub client_id: String,
    pub client_secret: String,
    pub name: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Stable subject identifier (the `sub` claim).
    pub id: String,
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Extra arbitrary claims merged into id_token / userinfo.
    #[serde(default)]
    pub claims: Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<SigningKey>,
    #[serde(default)]
    pub applications: Vec<Application>,
    #[serde(default)]
    pub users: Vec<User>,
}

impl Default for Store {
    fn default() -> Self {
        Store {
            port: default_port(),
            issuer: None,
            signing_key: None,
            applications: Vec::new(),
            users: Vec::new(),
        }
    }
}

impl Store {
    pub fn load(path: &Path) -> std::io::Result<Store> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let store: Store = serde_json::from_slice(&bytes)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(store)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Store::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
    }

    /// Compute the effective issuer URL (explicit override or localhost:port).
    pub fn issuer(&self) -> String {
        self.issuer
            .clone()
            .unwrap_or_else(|| format!("http://localhost:{}", self.port))
    }

    /// Return the signing key, generating and persisting one if absent.
    pub fn ensure_signing_key(&mut self, path: &Path) -> std::io::Result<&SigningKey> {
        if self.signing_key.is_none() {
            self.signing_key = Some(SigningKey {
                kid: crypto::random_kid(),
                private_pem: crypto::generate_private_pem(),
            });
            self.save(path)?;
        }
        Ok(self.signing_key.as_ref().unwrap())
    }

    pub fn find_app(&self, client_id: &str) -> Option<&Application> {
        self.applications.iter().find(|a| a.client_id == client_id)
    }

    pub fn find_user_by_name(&self, username: &str) -> Option<&User> {
        self.users.iter().find(|u| u.username == username)
    }
}
