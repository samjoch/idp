//! The mock OIDC server: discovery, JWKS, authorize, login, token, userinfo, logout.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::crypto;
use crate::models::{Application, Store, User};

const CODE_TTL: u64 = 300; // 5 minutes
const TOKEN_TTL: u64 = 3600; // 1 hour

/// Runtime state shared across requests.
pub struct ServerState {
    issuer: String,
    kid: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    jwks_n: String,
    jwks_e: String,
    apps: Vec<Application>,
    users: Vec<User>,
    codes: Mutex<HashMap<String, AuthCode>>,
    refresh: Mutex<HashMap<String, RefreshGrant>>,
}

struct AuthCode {
    client_id: String,
    user_id: String,
    redirect_uri: String,
    scope: String,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    expires_at: u64,
}

struct RefreshGrant {
    client_id: String,
    user_id: String,
    scope: String,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// UTC time-of-day stamp (HH:MM:SS) for log lines.
fn timestamp() -> String {
    let secs = now();
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Emit a server log line to stdout.
fn log(msg: &str) {
    println!("[{}] {}", timestamp(), msg);
}

/// Log every HTTP request with method, path, response status, and latency.
async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let start = Instant::now();
    let res = next.run(req).await;
    log(&format!(
        "{} {} -> {} ({}ms)",
        method,
        path,
        res.status().as_u16(),
        start.elapsed().as_millis()
    ));
    res
}

/// Build runtime state from the persisted store and start the HTTP server.
pub async fn run(mut store: Store, data_path: &Path) -> std::io::Result<()> {
    let key = store.ensure_signing_key(data_path)?.clone();
    let parts = crypto::public_parts(&key.private_pem);
    let issuer = store.issuer();
    let port = store.port;

    let state = Arc::new(ServerState {
        issuer: issuer.clone(),
        kid: key.kid.clone(),
        encoding_key: crypto::encoding_key(&key.private_pem),
        decoding_key: crypto::decoding_key(&parts),
        jwks_n: parts.n,
        jwks_e: parts.e,
        apps: store.applications.clone(),
        users: store.users.clone(),
        codes: Mutex::new(HashMap::new()),
        refresh: Mutex::new(HashMap::new()),
    });

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/login", post(login))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo).post(userinfo))
        .route("/logout", get(logout))
        .layer(from_fn(log_requests))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!("Mock OIDC IdP running");
    println!("  issuer:    {issuer}");
    println!("  discovery: {issuer}/.well-known/openid-configuration");
    println!("  listening: http://{addr}");
    println!(
        "  {} application(s), {} user(s) loaded",
        store.applications.len(),
        store.users.len()
    );
    println!("\nPress Ctrl+C to stop.");

    axum::serve(listener, app).await
}

// ---------------------------------------------------------------------------
// Discovery + JWKS
// ---------------------------------------------------------------------------

async fn discovery(State(s): State<Arc<ServerState>>) -> Json<Value> {
    let iss = &s.issuer;
    Json(json!({
        "issuer": iss,
        "authorization_endpoint": format!("{iss}/authorize"),
        "token_endpoint": format!("{iss}/token"),
        "userinfo_endpoint": format!("{iss}/userinfo"),
        "jwks_uri": format!("{iss}/jwks"),
        "end_session_endpoint": format!("{iss}/logout"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "name", "given_name", "family_name", "preferred_username",
            "email", "email_verified"
        ]
    }))
}

async fn jwks(State(s): State<Arc<ServerState>>) -> Json<Value> {
    Json(json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": s.kid,
            "n": s.jwks_n,
            "e": s.jwks_e,
        }]
    }))
}

// ---------------------------------------------------------------------------
// Authorization endpoint + login form
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AuthorizeParams {
    #[serde(default)]
    response_type: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    code_challenge: Option<String>,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    login_hint: Option<String>,
}

async fn authorize(
    State(s): State<Arc<ServerState>>,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    let client_id = match &p.client_id {
        Some(c) => c.clone(),
        None => return bad_request("missing client_id"),
    };
    let app = match s.apps.iter().find(|a| a.client_id == client_id) {
        Some(a) => a,
        None => return bad_request(&format!("unknown client_id: {client_id}")),
    };

    let redirect_uri = p.redirect_uri.clone().unwrap_or_default();
    if !app.redirect_uris.is_empty() && !app.redirect_uris.contains(&redirect_uri) {
        return bad_request(&format!(
            "redirect_uri not registered for this client: {redirect_uri}\nregistered: {:?}",
            app.redirect_uris
        ));
    }

    let scope = p.scope.clone().unwrap_or_else(|| "openid".into());
    log(&format!(
        "  authorize: client=\"{}\" scope=\"{}\" pkce={}",
        app.name,
        scope,
        p.code_challenge.is_some()
    ));
    Html(login_page(app, &p, &scope, &s.users)).into_response()
}

fn login_page(app: &Application, p: &AuthorizeParams, scope: &str, users: &[User]) -> String {
    let hidden = hidden_fields(&[
        ("response_type", p.response_type.as_deref().unwrap_or("code")),
        ("client_id", app.client_id.as_str()),
        ("redirect_uri", p.redirect_uri.as_deref().unwrap_or("")),
        ("scope", scope),
        ("state", p.state.as_deref().unwrap_or("")),
        ("nonce", p.nonce.as_deref().unwrap_or("")),
        ("code_challenge", p.code_challenge.as_deref().unwrap_or("")),
        (
            "code_challenge_method",
            p.code_challenge_method.as_deref().unwrap_or(""),
        ),
    ]);

    let quick: String = users
        .iter()
        .map(|u| {
            format!(
                r#"<form method="post" action="/login" class="quick">{hidden}
<input type="hidden" name="username" value="{user}">
<input type="hidden" name="quick" value="true">
<button type="submit">Sign in as <b>{user}</b>{email}</button>
</form>"#,
                hidden = hidden,
                user = esc(&u.username),
                email = if u.email.is_empty() {
                    String::new()
                } else {
                    format!(" — {}", esc(&u.email))
                },
            )
        })
        .collect();

    let prefill = p.login_hint.as_deref().unwrap_or("");

    format!(
        r#"<!doctype html>
<html><head><meta charset="utf-8"><title>Mock IdP — Sign in</title>
<style>
 body{{font-family:system-ui,sans-serif;max-width:30rem;margin:3rem auto;padding:0 1rem;color:#222}}
 h1{{font-size:1.3rem}} .app{{color:#555}} .scopes code{{background:#eee;padding:.1rem .3rem;border-radius:3px}}
 input{{display:block;width:100%;padding:.5rem;margin:.3rem 0;box-sizing:border-box}}
 button{{padding:.5rem .8rem;cursor:pointer}} .quick button{{width:100%;margin:.2rem 0;text-align:left}}
 hr{{margin:1.5rem 0;border:none;border-top:1px solid #ddd}}
 .muted{{color:#888;font-size:.85rem}}
</style></head><body>
<h1>Sign in</h1>
<p class="app"><b>{app}</b> is requesting access.</p>
<p class="scopes muted">scopes: <code>{scope}</code></p>
<form method="post" action="/login">{hidden}
 <input name="username" placeholder="username" value="{prefill}" autofocus>
 <input name="password" type="password" placeholder="password">
 <button type="submit">Sign in</button>
</form>
<hr>
<p class="muted">Quick sign-in (no password — mock only):</p>
{quick}
</body></html>"#,
        app = esc(&app.name),
        scope = esc(scope),
        hidden = hidden,
        prefill = esc(prefill),
        quick = quick,
    )
}

#[derive(Debug, Deserialize)]
struct LoginForm {
    #[serde(default)]
    username: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    quick: Option<String>,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    nonce: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
}

async fn login(State(s): State<Arc<ServerState>>, Form(f): Form<LoginForm>) -> Response {
    let user = match s.users.iter().find(|u| u.username == f.username) {
        Some(u) => u,
        None => return bad_request(&format!("unknown user: {}", f.username)),
    };

    let is_quick = matches!(f.quick.as_deref(), Some("true") | Some("1") | Some("on"));
    if !is_quick && user.password != f.password {
        return bad_request("invalid password");
    }

    let code = crypto::random_token(24);
    {
        let mut codes = s.codes.lock().unwrap();
        codes.insert(
            code.clone(),
            AuthCode {
                client_id: f.client_id.clone(),
                user_id: user.id.clone(),
                redirect_uri: f.redirect_uri.clone(),
                scope: f.scope.clone(),
                nonce: non_empty(f.nonce),
                code_challenge: non_empty(f.code_challenge),
                code_challenge_method: non_empty(f.code_challenge_method),
                expires_at: now() + CODE_TTL,
            },
        );
    }

    log(&format!(
        "  login OK: user=\"{}\" ({}) -> code issued, redirecting to {}",
        user.username,
        if is_quick { "quick" } else { "password" },
        f.redirect_uri
    ));

    let mut params = vec![("code", code.as_str())];
    if !f.state.is_empty() {
        params.push(("state", f.state.as_str()));
    }
    Redirect::to(&build_url(&f.redirect_uri, &params)).into_response()
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TokenForm {
    #[serde(default)]
    grant_type: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<String>,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn token(
    State(s): State<Arc<ServerState>>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> Response {
    // Resolve client credentials from Basic auth header or POST body.
    let (client_id, client_secret) = match basic_auth(&headers) {
        Some(pair) => pair,
        None => (
            f.client_id.clone().unwrap_or_default(),
            f.client_secret.clone(),
        ),
    };

    log(&format!(
        "  token: grant_type={} client_id={}",
        if f.grant_type.is_empty() { "(none)" } else { &f.grant_type },
        if client_id.is_empty() { "(none)" } else { &client_id }
    ));

    match f.grant_type.as_str() {
        "authorization_code" => token_auth_code(&s, &f, &client_id, client_secret.as_deref()),
        "refresh_token" => token_refresh(&s, &f, &client_id, client_secret.as_deref()),
        "client_credentials" => token_client_credentials(&s, &f, &client_id, client_secret.as_deref()),
        other => oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("unsupported grant_type: {other}"),
        ),
    }
}

fn token_auth_code(
    s: &ServerState,
    f: &TokenForm,
    client_id: &str,
    client_secret: Option<&str>,
) -> Response {
    let code = match &f.code {
        Some(c) => c.clone(),
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing code"),
    };

    let entry = { s.codes.lock().unwrap().remove(&code) };
    let entry = match entry {
        Some(e) => e,
        None => {
            return oauth_error(
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "unknown or already-used code",
            )
        }
    };

    if entry.expires_at < now() {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "code expired");
    }
    if entry.client_id != client_id {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "code was issued to a different client",
        );
    }
    if let Some(ru) = &f.redirect_uri {
        if ru != &entry.redirect_uri {
            return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "redirect_uri mismatch");
        }
    }

    let app = match s.apps.iter().find(|a| a.client_id == client_id) {
        Some(a) => a,
        None => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };

    // Authenticate: a valid PKCE verifier OR a matching secret is required when
    // the client has a secret. Public clients (PKCE only) skip the secret check.
    let pkce_ok = match &entry.code_challenge {
        Some(challenge) => {
            let method = entry.code_challenge_method.as_deref().unwrap_or("plain");
            match &f.code_verifier {
                Some(v) => crypto::verify_pkce(v, challenge, method),
                None => false,
            }
        }
        None => false,
    };
    let secret_ok = client_secret.map(|sec| sec == app.client_secret).unwrap_or(false);

    if entry.code_challenge.is_some() && !pkce_ok && !secret_ok {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "PKCE verification failed");
    }
    if entry.code_challenge.is_none() && !secret_ok && client_secret.is_some() {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "bad client_secret");
    }

    let user = match s.users.iter().find(|u| u.id == entry.user_id) {
        Some(u) => u,
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "user no longer exists"),
    };

    issue_tokens(s, user, client_id, &entry.scope, entry.nonce.as_deref(), true)
}

fn token_refresh(
    s: &ServerState,
    f: &TokenForm,
    client_id: &str,
    client_secret: Option<&str>,
) -> Response {
    let rt = match &f.refresh_token {
        Some(t) => t.clone(),
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request", "missing refresh_token"),
    };
    let grant = { s.refresh.lock().unwrap().remove(&rt) };
    let grant = match grant {
        Some(g) => g,
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown refresh_token"),
    };
    if grant.client_id != client_id {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "client mismatch");
    }
    if let Some(app) = s.apps.iter().find(|a| a.client_id == client_id) {
        if let Some(sec) = client_secret {
            if sec != app.client_secret {
                return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "bad client_secret");
            }
        }
    }
    let user = match s.users.iter().find(|u| u.id == grant.user_id) {
        Some(u) => u,
        None => return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "user no longer exists"),
    };
    let scope = f.scope.clone().unwrap_or(grant.scope);
    issue_tokens(s, user, client_id, &scope, None, true)
}

fn token_client_credentials(
    s: &ServerState,
    f: &TokenForm,
    client_id: &str,
    client_secret: Option<&str>,
) -> Response {
    let app = match s.apps.iter().find(|a| a.client_id == client_id) {
        Some(a) => a,
        None => return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "unknown client"),
    };
    if client_secret != Some(app.client_secret.as_str()) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", "bad client_secret");
    }
    let scope = f.scope.clone().unwrap_or_default();
    let access = make_access_token(s, client_id, client_id, &scope);
    log(&format!(
        "  tokens issued: client_credentials client={} scope=\"{}\"",
        client_id, scope
    ));
    Json(json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": scope,
    }))
    .into_response()
}

fn issue_tokens(
    s: &ServerState,
    user: &User,
    client_id: &str,
    scope: &str,
    nonce: Option<&str>,
    with_refresh: bool,
) -> Response {
    let scopes = scope_list(scope);
    let access = make_access_token(s, &user.id, client_id, scope);
    let mut body = json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL,
        "scope": scope,
    });

    if scopes.iter().any(|x| x == "openid") {
        body["id_token"] = json!(make_id_token(s, user, client_id, nonce, &scopes));
    }

    let mut refreshed = false;
    if with_refresh && scopes.iter().any(|x| x == "offline_access") {
        let rt = crypto::random_token(32);
        s.refresh.lock().unwrap().insert(
            rt.clone(),
            RefreshGrant {
                client_id: client_id.to_string(),
                user_id: user.id.clone(),
                scope: scope.to_string(),
            },
        );
        body["refresh_token"] = json!(rt);
        refreshed = true;
    }

    log(&format!(
        "  tokens issued: sub={} client={} scope=\"{}\" id_token={} refresh_token={}",
        user.id,
        client_id,
        scope,
        body.get("id_token").is_some(),
        refreshed
    ));

    Json(body).into_response()
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

async fn userinfo(State(s): State<Arc<ServerState>>, headers: HeaderMap) -> Response {
    let token = match bearer_token(&headers) {
        Some(t) => t,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                "missing bearer token",
            )
                .into_response()
        }
    };

    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    let data = match decode::<Value>(&token, &s.decoding_key, &validation) {
        Ok(d) => d,
        Err(e) => {
            return oauth_error(StatusCode::UNAUTHORIZED, "invalid_token", &e.to_string())
        }
    };

    let claims = data.claims;
    let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
    let scope = claims.get("scope").and_then(|v| v.as_str()).unwrap_or("");
    let scopes = scope_list(scope);

    log(&format!("  userinfo: sub={sub}"));
    let mut out = Map::new();
    out.insert("sub".into(), json!(sub));
    if let Some(user) = s.users.iter().find(|u| u.id == sub) {
        for (k, v) in user_claims(user, &scopes) {
            out.insert(k, v);
        }
    }
    Json(Value::Object(out)).into_response()
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LogoutParams {
    #[serde(default)]
    post_logout_redirect_uri: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

async fn logout(Query(p): Query<LogoutParams>) -> Response {
    match p.post_logout_redirect_uri {
        Some(uri) if !uri.is_empty() => {
            let mut params = vec![];
            if let Some(st) = &p.state {
                if !st.is_empty() {
                    params.push(("state", st.as_str()));
                }
            }
            Redirect::to(&build_url(&uri, &params)).into_response()
        }
        _ => Html("<!doctype html><p>You have been signed out.</p>").into_response(),
    }
}

// ---------------------------------------------------------------------------
// Claims + signing
// ---------------------------------------------------------------------------

fn scope_list(scope: &str) -> Vec<String> {
    scope.split_whitespace().map(String::from).collect()
}

fn user_claims(user: &User, scopes: &[String]) -> Map<String, Value> {
    let mut m = Map::new();
    let has = |name: &str| scopes.iter().any(|s| s == name);

    if has("profile") {
        if !user.name.is_empty() {
            m.insert("name".into(), json!(user.name));
        }
        if let Some(g) = &user.given_name {
            m.insert("given_name".into(), json!(g));
        }
        if let Some(fam) = &user.family_name {
            m.insert("family_name".into(), json!(fam));
        }
        m.insert("preferred_username".into(), json!(user.username));
    }
    if has("email") {
        if !user.email.is_empty() {
            m.insert("email".into(), json!(user.email));
        }
        m.insert("email_verified".into(), json!(user.email_verified));
    }
    for (k, v) in &user.claims {
        m.insert(k.clone(), v.clone());
    }
    m
}

fn make_id_token(
    s: &ServerState,
    user: &User,
    client_id: &str,
    nonce: Option<&str>,
    scopes: &[String],
) -> String {
    let t = now();
    let mut claims = user_claims(user, scopes);
    claims.insert("sub".into(), json!(user.id));
    claims.insert("iss".into(), json!(s.issuer));
    claims.insert("aud".into(), json!(client_id));
    claims.insert("iat".into(), json!(t));
    claims.insert("auth_time".into(), json!(t));
    claims.insert("exp".into(), json!(t + TOKEN_TTL));
    if let Some(n) = nonce {
        claims.insert("nonce".into(), json!(n));
    }
    sign(s, &Value::Object(claims))
}

fn make_access_token(s: &ServerState, sub: &str, client_id: &str, scope: &str) -> String {
    let t = now();
    let claims = json!({
        "iss": s.issuer,
        "sub": sub,
        "aud": s.issuer,
        "client_id": client_id,
        "scope": scope,
        "iat": t,
        "exp": t + TOKEN_TTL,
        "jti": crypto::random_token(8),
        "typ": "at+jwt",
    });
    sign(s, &claims)
}

fn sign(s: &ServerState, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(s.kid.clone());
    encode(&header, claims, &s.encoding_key).expect("failed to sign JWT")
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn bad_request(msg: &str) -> Response {
    log(&format!("  ! bad request: {msg}"));
    (StatusCode::BAD_REQUEST, Html(format!("<pre>{}</pre>", esc(msg)))).into_response()
}

fn oauth_error(status: StatusCode, error: &str, desc: &str) -> Response {
    log(&format!("  ! {} ({}): {}", error, status.as_u16(), desc));
    (
        status,
        Json(json!({ "error": error, "error_description": desc })),
    )
        .into_response()
}

fn basic_auth(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = raw.strip_prefix("Basic ").or_else(|| raw.strip_prefix("basic "))?;
    let decoded = BASE64_STD.decode(b64.trim()).ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (id, secret) = text.split_once(':')?;
    let id = urlencoding::decode(id).map(|c| c.into_owned()).unwrap_or_else(|_| id.to_string());
    let secret = urlencoding::decode(secret)
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| secret.to_string());
    Some((id, Some(secret)))
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(|t| t.trim().to_string())
}

fn build_url(base: &str, params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return base.to_string();
    }
    let sep = if base.contains('?') { '&' } else { '?' };
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencoding::encode(v)))
        .collect();
    format!("{}{}{}", base, sep, query.join("&"))
}

fn hidden_fields(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(k, v)| format!(r#"<input type="hidden" name="{}" value="{}">"#, k, esc(v)))
        .collect()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// Minimal HTML escaping for attribute/text contexts.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
