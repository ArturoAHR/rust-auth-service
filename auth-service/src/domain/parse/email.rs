use std::hash::{Hash, Hasher};

use secrecy::{ExposeSecret, SecretString};
use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum EmailParseError {
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Empty email")]
    EmptyEmail,
}

#[derive(Debug, Clone)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Hash for Email {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Eq for Email {}

impl Email {
    pub fn parse(email: SecretString) -> Result<Self, EmailParseError> {
        if email.expose_secret().len() == 0 {
            return Err(EmailParseError::EmptyEmail);
        }

        if !email.expose_secret().contains("@") {
            return Err(EmailParseError::InvalidEmail);
        }

        Ok(Email(email))
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        return &self.0;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn should_parse_valid_email() {
        let email_str = SecretString::new("example@email.com".to_owned().into_boxed_str());

        let email = Email::parse(email_str.clone()).unwrap();

        assert_eq!(email.0.expose_secret(), email_str.expose_secret());
    }

    #[test]
    fn should_fail_to_parse_empty_email() {
        let email_str = SecretString::new("".to_owned().into_boxed_str());

        let email_error = Email::parse(email_str.clone()).err().unwrap();

        assert_eq!(email_error, EmailParseError::EmptyEmail);
    }

    #[test]
    fn should_fail_to_parse_invalid_emails() {
        let email_str = SecretString::new("invalid-email".to_owned().into_boxed_str());

        let email_error = Email::parse(email_str.clone()).err().unwrap();

        assert_eq!(email_error, EmailParseError::InvalidEmail);
    }
}
