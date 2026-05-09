use std::env;

use dotenvy::dotenv;
use lazy_static::lazy_static;

pub const JWT_COOKIE_NAME: &str = "jwt";

lazy_static! {
    pub static ref JWT_SECRET: String = get_jwt_secret();
}

fn get_jwt_secret() -> String {
    dotenv().ok();

    let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set.");

    if secret.is_empty() {
        panic!("JWT_SECRET must not be empty.");
    }

    secret
}
lazy_static! {
    pub static ref DATABASE_URL: String = get_database_url();
}

fn get_database_url() -> String {
    dotenv().ok();

    let secret = env::var("DATABASE_URL").expect("DATABASE_URL must be set.");

    if secret.is_empty() {
        panic!("DATABASE_URL must not be empty.");
    }

    secret
}

pub mod prod {
    pub const APP_ADDRESS: &str = "0.0.0.0:3000";
}

pub mod test {
    pub const APP_ADDRESS: &str = "127.0.0.1:0";
}
