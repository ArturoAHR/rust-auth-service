use color_eyre::eyre::{Context, Result};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct LoginAttemptId(String);

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        Uuid::parse_str(&id).wrap_err("Login attempt identifier parse failed")?;

        Ok(LoginAttemptId(id))
    }
}

impl Default for LoginAttemptId {
    /// Generates a random login attempt identifier uuid.
    fn default() -> Self {
        let uuid = Uuid::new_v4();

        LoginAttemptId(uuid.to_string())
    }
}

impl AsRef<str> for LoginAttemptId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
