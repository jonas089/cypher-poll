// GitHub authentication
// should check the Github API for associated GPG keys and return them as a Vec
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, USER_AGENT};
use std::env;
use crate::constants::GITHUB_GPG_ROUTE;

pub async fn query_user_gpg_keys() -> String{
    let client = reqwest::Client::new();
    // Headers
    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/vnd.github+json"));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", env::var("GITHUB_TOKEN").unwrap())).unwrap());
    headers.insert(USER_AGENT, HeaderValue::from_static("Acropolis (jonaspauli089@gmail.com)"));
    // Custom GitHub API version header
    headers.insert("X-GitHub-Api-Version", HeaderValue::from_static("2022-11-28"));

    // Making the GET request
    let response = client.get(GITHUB_GPG_ROUTE)
        .headers(headers)
        .send()
        .await.expect("Failed to get response from GitHub api");

    response.text().await.expect("Failed to unwrap response")
    // todo: Github Token
    // todo: Request to:
    /*
    curl -L \
        -H "Accept: application/vnd.github+json" \
        -H "Authorization: Bearer <YOUR-TOKEN>" \
        -H "X-GitHub-Api-Version: 2022-11-28" \
        https://api.github.com/user/gpg_keys
    */
}

#[tokio::test]
async fn test_query_gpg(){
    let response = query_user_gpg_keys().await;
    println!("Response: {:?}", &response);
}