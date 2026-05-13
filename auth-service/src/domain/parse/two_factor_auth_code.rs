use color_eyre::eyre::{eyre, Result};
use rand::RngExt;
use secrecy::{ExposeSecret, SecretString};

#[derive(Clone, Debug)]
pub struct TwoFactorAuthCode(SecretString);

impl PartialEq for TwoFactorAuthCode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFactorAuthCode {
    pub fn parse(code: SecretString) -> Result<Self> {
        if code.expose_secret().len() != 6
            || code
                .expose_secret()
                .chars()
                .any(|digit| !digit.is_ascii_digit())
        {
            return Err(eyre!("Invalid code".to_owned()));
        }

        Ok(TwoFactorAuthCode(code))
    }
}

impl Default for TwoFactorAuthCode {
    /// Generates a random two factor auth code.
    fn default() -> Self {
        let mut rng = rand::rng();

        let code_number = rng.random_range(100_000..=999_999);

        TwoFactorAuthCode(SecretString::new(code_number.to_string().into_boxed_str()))
    }
}

impl AsRef<SecretString> for TwoFactorAuthCode {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}
