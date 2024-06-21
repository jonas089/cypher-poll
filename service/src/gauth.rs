// GitHub authentication
// should check the Github API for associated GPG keys and return them as a Vec
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION};
use std::env;

pub fn query_user_gpg_keys(){
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