#[derive(Debug, PartialEq)]
enum PasswordParseError {
    InsufficientLength,
}

pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Self, PasswordParseError> {
        if password.len() < 8 {
            return Err(PasswordParseError::InsufficientLength);
        }

        Ok(Password(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        return &self.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_parse_valid_password() {
        let password_str = "password12345".to_owned();

        let password = Password::parse(password_str.clone()).unwrap();

        assert_eq!(password.0, password_str);
    }

    #[test]
    fn should_fail_to_parse_too_short_passwords() {
        let password_str = "short".to_owned();

        let password_error = Password::parse(password_str.clone()).err().unwrap();

        assert_eq!(password_error, PasswordParseError::InsufficientLength);
    }
}
