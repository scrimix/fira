use chrono::{Datelike, Duration, NaiveDate, TimeZone, Utc, Weekday};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use reqwest::Client;
use std::env;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();

    // Create an OAuth2 client by specifying the client ID, client secret, authorization URL and
    // token URL.
    let client = BasicClient::new(ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap()))
        .set_client_secret(ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap()))
        .set_auth_uri(
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
        )
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap())
        .set_redirect_uri(
            RedirectUrl::new("http://localhost:8000/auth/callback".to_string()).unwrap(),
        );

    // let client = BasicClient::new(
    //     ClientId::new(env::var("GOOGLE_CLIENT_ID").unwrap()),
    //     Some(ClientSecret::new(env::var("GOOGLE_CLIENT_SECRET").unwrap())),
    //     AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
    //     Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string()).unwrap()),
    // )
    // .set_redirect_uri(RedirectUrl::new("http://localhost:8000/auth/callback".to_string()).unwrap());

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            "https://www.googleapis.com/auth/calendar.readonly".to_string(),
        ))
        .url();

    println!("Browse to: {}", auth_url);

    // For simplicity: paste the code manually
    println!("Paste the `code` from Google here:");
    let mut code = String::new();
    std::io::stdin().read_line(&mut code).unwrap();
    let code = code.trim().to_string();

    let http_client = reqwest::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    let token_result = client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .request_async(&http_client)
        .await
        .unwrap();

    let access_token = token_result.access_token().secret();

    let today = Utc::now();
    let start_of_week_naive =
        NaiveDate::from_isoywd_opt(today.year(), today.iso_week().week(), Weekday::Mon)
            .unwrap()
            .and_hms_opt(0, 0, 0)
            .unwrap();
    let start_of_week = Utc.from_utc_datetime(&start_of_week_naive);

    let end_of_week = start_of_week + Duration::days(7);

    // Call Google Calendar API
    // let calendar_url = "https://www.googleapis.com/calendar/v3/calendars/primary/events";

    let calendar_url = format!(
        "https://www.googleapis.com/calendar/v3/calendars/primary/events?\
        timeMin={}&timeMax={}&singleEvents=true&orderBy=startTime",
        start_of_week.to_rfc3339(),
        end_of_week.to_rfc3339()
    );

    let res = Client::new()
        .get(calendar_url)
        .bearer_auth(access_token)
        .send()
        .await
        .unwrap();

    let body = res.text().await.unwrap();
    println!("Calendar events: {}", body);
}
