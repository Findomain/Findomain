use std::env;

pub fn get_auth_token(api: &str) -> String {
    if api == "facebook" {
        match env::var("findomain_fb_token") {
            Ok(token) => token,
            Err(_) => String::from(""),
        }
    } else {
        String::from("")
    }
}
