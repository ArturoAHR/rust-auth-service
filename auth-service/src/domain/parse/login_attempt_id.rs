use color_eyre::eyre::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct LoginAttemptId(SecretString);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: SecretString) -> Result<Self> {
        Uuid::parse_str(&id.expose_secret()).wrap_err("Login attempt identifier parse failed")?;

        Ok(LoginAttemptId(id))
    }
}

impl Default for LoginAttemptId {
    /// Generates a random login attempt identifier uuid.
    fn default() -> Self {
        let uuid = Uuid::new_v4();

        LoginAttemptId(SecretString::new(uuid.to_string().into_boxed_str()))
    }
}

impl AsRef<SecretString> for LoginAttemptId {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}
