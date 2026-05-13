use dotenvy::dotenv;
use lazy_static::lazy_static;
use secrecy::SecretString;

pub mod env {
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
    pub const POSTMARK_AUTH_TOKEN_ENV_VAR: &str = "POSTMARK_AUTH_TOKEN";
}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";

    pub mod email_client {
        use std::time::Duration;

        pub const BASE_URL: &str = "https://api.postmarkapp.com/email";
        pub const SENDER: &str = "bogdan@codeiron.io";
        pub const TIMEOUT: Duration = Duration::from_secs(10);
    }
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";

    pub mod email_client {
        use std::time::Duration;

        pub const SENDER: &str = "test@email.com";
        pub const TIMEOUT: Duration = Duration::from_millis(200);
    }
}

lazy_static! {
    pub static ref JWT_SECRET: SecretString =
        get_secret_environment_variable(env::JWT_SECRET_ENV_VAR);
    pub static ref DATABASE_URL: SecretString =
        get_secret_environment_variable(env::DATABASE_URL_ENV_VAR);
    pub static ref REDIS_HOST_NAME: String = get_environment_variable(env::REDIS_HOST_NAME_ENV_VAR);
    pub static ref POSTMARK_AUTH_TOKEN: SecretString =
        get_secret_environment_variable(env::POSTMARK_AUTH_TOKEN_ENV_VAR);
}

fn get_environment_variable(variable_name: &str) -> String {
    dotenv().ok();

    let variable =
        std::env::var(variable_name).expect(format!("{variable_name} must be set.").as_str());

    if variable.is_empty() {
        panic!("{variable_name} must not be empty.");
    }

    variable
}

fn get_secret_environment_variable(variable_name: &str) -> SecretString {
    dotenv().ok();

    let secret =
        std::env::var(variable_name).expect(format!("{variable_name} must be set.").as_str());

    if secret.is_empty() {
        panic!("{variable_name} must not be empty.");
    }

    SecretString::new(secret.into_boxed_str())
}
