use thiserror::Error;

#[derive(Debug, PartialEq, Error)]
pub enum EmailParseError {
    #[error("Invalid email")]
    InvalidEmail,
    #[error("Empty email")]
    EmptyEmail,
}

#[derive(Debug, PartialEq, Clone, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, EmailParseError> {
        if email.len() == 0 {
            return Err(EmailParseError::EmptyEmail);
        }

        if !email.contains("@") {
            return Err(EmailParseError::InvalidEmail);
        }

        Ok(Email(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        return &self.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_valid_email() {
        let email_str = "example@email.com".to_owned();

        let email = Email::parse(email_str.clone()).unwrap();

        assert_eq!(email.0, email_str);
    }

    #[test]
    fn should_fail_to_parse_empty_email() {
        let email_str = "".to_owned();

        let email_error = Email::parse(email_str.clone()).err().unwrap();

        assert_eq!(email_error, EmailParseError::EmptyEmail);
    }

    #[test]
    fn should_fail_to_parse_invalid_emails() {
        let email_str = "invalid-email".to_owned();

        let email_error = Email::parse(email_str.clone()).err().unwrap();

        assert_eq!(email_error, EmailParseError::InvalidEmail);
    }
}
