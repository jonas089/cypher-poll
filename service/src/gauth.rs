// GitHub authentication
// should check the Github API for associated GPG keys and return them as a Vec
use crate::constants::GIT_GPG_URL;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use serde_json::Value;

pub async fn query_user_gpg_keys(token: String) -> Vec<String> {
    let client = reqwest::Client::new();
    // Headers
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("application/vnd.github+json"),
    );
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
    );
    headers.insert(
        USER_AGENT,
        HeaderValue::from_static("Acropolis V2 (jonaspauli089@gmail.com)"),
    );
    // Custom GitHub API version header
    headers.insert(
        "X-GitHub-Api-Version",
        HeaderValue::from_static("2022-11-28"),
    );

    // Making the GET request
    let response = client
        .get(GIT_GPG_URL)
        .headers(headers)
        .send()
        .await
        .expect("Failed to get response from GitHub api");
    let response = response.text().await.expect("Failed to unwrap response");
    let json_keys: Value = serde_json::from_str(&response).unwrap();
    let mut raw_keys: Vec<String> = Vec::new();
    if let Some(array) = json_keys.as_array() {
        for item in array {
            let raw_key = item["raw_key"].to_string();
            let mut formatted_key = raw_key
                .replace("\\r\\n", "\n")
                .trim_start_matches('"')
                .trim_end_matches('"')
                .to_string();
            formatted_key.push_str("\n");
            raw_keys.push(formatted_key);
        }
    }
    raw_keys
}
