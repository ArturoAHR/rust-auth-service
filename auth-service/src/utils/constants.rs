use dotenvy::dotenv;
use lazy_static::lazy_static;

pub mod env {
    pub const DATABASE_URL_ENV_VAR: &str = "DATABASE_URL";
    pub const JWT_SECRET_ENV_VAR: &str = "JWT_SECRET";
    pub const REDIS_HOST_NAME_ENV_VAR: &str = "REDIS_HOST_NAME";
}

pub const JWT_COOKIE_NAME: &str = "jwt";

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}

lazy_static! {
    pub static ref JWT_SECRET: String = get_jwt_secret();
    pub static ref DATABASE_URL: String = get_database_url();
    pub static ref REDIS_HOST_NAME: String = get_redis_host();
}

fn get_jwt_secret() -> String {
    dotenv().ok();

    let secret = std::env::var(env::JWT_SECRET_ENV_VAR).expect("JWT_SECRET must be set.");

    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }

    secret
}

fn get_database_url() -> String {
    dotenv().ok();

    let secret = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set.");

    if secret.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }

    secret
}

fn get_redis_host() -> String {
    dotenv().ok();

    let secret = std::env::var(env::REDIS_HOST_NAME_ENV_VAR).expect("REDIS_HOST_NAME must be set.");

    if secret.is_empty() {
        panic!("REDIS_HOST_NAME must not be empty.");
    }

    secret
}
