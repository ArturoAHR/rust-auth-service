use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretString};
use tracing::{instrument, Span};

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    #[instrument(name = "Hash Password", skip_all)]
    pub async fn parse(password: SecretString) -> Result<Self> {
        if password.expose_secret().len() < 8 {
            return Err(eyre!("Insufficient password length".to_owned()));
        }

        let hashed_password = compute_password_hash(&password).await?;

        Ok(HashedPassword(hashed_password))
    }

    #[instrument(name = "Parse Hashed Password", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<Self> {
        PasswordHash::new(&hash.expose_secret().as_ref())
            .wrap_err("Failed to parse string to a hashed password")?;

        Ok(HashedPassword(hash))
    }

    #[instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(&self, password_candidate: &SecretString) -> Result<()> {
        let current_span = Span::current();
        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.to_owned();

        tokio::task::spawn_blocking(move || -> Result<()> {
            current_span.in_scope(|| {
                let expected_password_hash: PasswordHash = PasswordHash::new(&password_hash)?;

                Argon2::default()
                    .verify_password(
                        password_candidate.expose_secret().as_bytes(),
                        &expected_password_hash,
                    )
                    .map_err(|e| e.into())
            })
        })
        .await?
    }
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        return &self.0;
    }
}

#[instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span = Span::current();
    let password = password.expose_secret().to_owned();

    let salt: SaltString = SaltString::generate(&mut OsRng);

    tokio::task::spawn_blocking(move || -> Result<SecretString> {
        current_span.in_scope(|| {
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();

            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use fake::faker::internet::en::Password as FakePassword;
    use fake::Fake;
    use quickcheck::Gen;
    use rand::SeedableRng;
    use secrecy::{ExposeSecret, SecretString};

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password: SecretString = SecretString::new("".to_owned().into_boxed_str());

        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password: SecretString = SecretString::new("1234567".to_owned().into_boxed_str());

        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = SecretString::new(
            argon2
                .hash_password(raw_password.as_bytes(), &salt)
                .unwrap()
                .to_string()
                .into_boxed_str(),
        );

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(
            hash_password.as_ref().expose_secret(),
            hash_string.expose_secret()
        );
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = SecretString::new("TestPassword123".to_owned().into_boxed_str());
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = SecretString::new(
            argon2
                .hash_password(raw_password.expose_secret().as_bytes(), &salt)
                .unwrap()
                .to_string()
                .into_boxed_str(),
        );

        let hash_password = HashedPassword::parse_password_hash(hash_string.clone()).unwrap();

        assert_eq!(
            hash_password.as_ref().expose_secret(),
            hash_string.expose_secret()
        );
        assert!(hash_password
            .as_ref()
            .expose_secret()
            .starts_with("$argon2id$v=19$"));

        let result = hash_password
            .verify_raw_password(&raw_password)
            .await
            .unwrap();

        assert_eq!(result, ());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub String);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(g: &mut Gen) -> Self {
            let seed: u64 = g.size() as u64;
            let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
            let password = FakePassword(8..30).fake_with_rng(&mut rng);
            Self(password)
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(SecretString::new(valid_password.0.into_boxed_str()))
            .await
            .is_ok()
    }
}
