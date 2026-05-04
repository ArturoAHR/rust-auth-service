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
        panic!("JWT_SECRET must not be empty.")
    }

    secret
}
