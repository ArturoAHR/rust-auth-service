use rand::RngExt;

#[derive(Clone, Debug, PartialEq)]
pub struct TwoFactorAuthCode(String);

impl TwoFactorAuthCode {
    pub fn parse(code: String) -> Result<Self, String> {
        if code.len() != 6 || code.chars().any(|digit| !digit.is_ascii_digit()) {
            return Err("Invalid code".to_owned());
        }

        Ok(TwoFactorAuthCode(code))
    }
}

impl Default for TwoFactorAuthCode {
    /// Generates a random two factor auth code.
    fn default() -> Self {
        let mut rng = rand::rng();

        let code_number = rng.random_range(100_000..=999_999);

        TwoFactorAuthCode(code_number.to_string())
    }
}

impl AsRef<str> for TwoFactorAuthCode {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
