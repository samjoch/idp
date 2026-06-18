//! `idp` — a mock OpenID Connect Identity Provider for local testing.
//!
//! Manage applications and users from the CLI, then start a server that speaks
//! enough OIDC (discovery, authorize, token, userinfo, jwks) to drive a real
//! client through the Authorization Code flow.

mod crypto;
mod models;
mod server;

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use uuid::Uuid;

use models::{Application, Store, User};

#[derive(Parser)]
#[command(name = "idp", version, about = "Mock OIDC Identity Provider for testing")]
struct Cli {
    /// Path to the JSON data file (applications, users, signing key).
    #[arg(long, global = true, default_value = "idp-data.json", env = "IDP_DATA")]
    data: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage OIDC applications (clients).
    App {
        #[command(subcommand)]
        cmd: AppCmd,
    },
    /// Manage users.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Start the OIDC server.
    Serve {
        /// Port to listen on (persisted to the data file).
        #[arg(long)]
        port: Option<u16>,
        /// Override the issuer URL (default: http://localhost:<port>).
        #[arg(long)]
        issuer: Option<String>,
    },
    /// Print everything needed to configure an external app.
    Info {
        /// Only show settings for a single application.
        #[arg(long)]
        client_id: Option<String>,
        /// Emit machine-readable JSON instead of a human summary.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AppCmd {
    /// Register a new application and print its credentials.
    Create {
        /// Human-readable application name.
        name: String,
        /// Allowed redirect URI (repeatable).
        #[arg(long = "redirect-uri", value_name = "URL")]
        redirect_uris: Vec<String>,
        /// Allowed post-logout redirect URI (repeatable).
        #[arg(long = "logout-uri", value_name = "URL")]
        logout_uris: Vec<String>,
        /// Allowed scope (repeatable). Defaults to: openid profile email offline_access.
        #[arg(long = "scope", value_name = "SCOPE")]
        scopes: Vec<String>,
    },
    /// List registered applications.
    List,
    /// Show one application in detail.
    Show { client_id: String },
    /// Delete an application.
    Delete { client_id: String },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Create a user.
    Create {
        username: String,
        #[arg(long, default_value = "password")]
        password: String,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        given_name: Option<String>,
        #[arg(long)]
        family_name: Option<String>,
        /// Mark the email as verified.
        #[arg(long)]
        email_verified: bool,
        /// Stable subject id (defaults to a random UUID).
        #[arg(long)]
        sub: Option<String>,
    },
    /// List users.
    List,
    /// Delete a user by username.
    Delete { username: String },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let path = cli.data;
    let mut store = Store::load(&path)?;

    match cli.command {
        Command::App { cmd } => app_command(&mut store, &path, cmd)?,
        Command::User { cmd } => user_command(&mut store, &path, cmd)?,
        Command::Info { client_id, json } => info_command(&store, client_id, json),
        Command::Serve { port, issuer } => {
            if let Some(p) = port {
                store.port = p;
            }
            if let Some(iss) = issuer {
                store.issuer = Some(iss);
            }
            store.save(&path)?;
            server::run(store, &path).await?;
        }
    }
    Ok(())
}

fn app_command(
    store: &mut Store,
    path: &std::path::Path,
    cmd: AppCmd,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AppCmd::Create {
            name,
            redirect_uris,
            logout_uris,
            scopes,
        } => {
            let scopes = if scopes.is_empty() {
                vec![
                    "openid".into(),
                    "profile".into(),
                    "email".into(),
                    "offline_access".into(),
                ]
            } else {
                scopes
            };
            let app = Application {
                client_id: Uuid::new_v4().to_string(),
                client_secret: crypto::random_token(32),
                name,
                redirect_uris,
                post_logout_redirect_uris: logout_uris,
                scopes,
            };
            store.applications.push(app.clone());
            store.save(path)?;
            println!("Application created.\n");
            print_app(&app);
            if app.redirect_uris.is_empty() {
                println!(
                    "\nnote: no redirect URIs registered — any redirect_uri will be accepted."
                );
            }
        }
        AppCmd::List => {
            if store.applications.is_empty() {
                println!("No applications. Create one with: idp app create <name> --redirect-uri <url>");
            }
            for a in &store.applications {
                println!("{}  {}  ({} redirect URIs)", a.client_id, a.name, a.redirect_uris.len());
            }
        }
        AppCmd::Show { client_id } => match store.find_app(&client_id) {
            Some(a) => print_app(a),
            None => return Err(format!("no application with client_id {client_id}").into()),
        },
        AppCmd::Delete { client_id } => {
            let before = store.applications.len();
            store.applications.retain(|a| a.client_id != client_id);
            if store.applications.len() == before {
                return Err(format!("no application with client_id {client_id}").into());
            }
            store.save(path)?;
            println!("Deleted application {client_id}.");
        }
    }
    Ok(())
}

fn user_command(
    store: &mut Store,
    path: &std::path::Path,
    cmd: UserCmd,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        UserCmd::Create {
            username,
            password,
            email,
            name,
            given_name,
            family_name,
            email_verified,
            sub,
        } => {
            if store.find_user_by_name(&username).is_some() {
                return Err(format!("user '{username}' already exists").into());
            }
            let user = User {
                id: sub.unwrap_or_else(|| Uuid::new_v4().to_string()),
                username: username.clone(),
                password,
                email: email.unwrap_or_default(),
                email_verified,
                name: name.unwrap_or_else(|| username.clone()),
                given_name,
                family_name,
                claims: Default::default(),
            };
            store.users.push(user.clone());
            store.save(path)?;
            println!("User created.");
            println!("  sub:      {}", user.id);
            println!("  username: {}", user.username);
            println!("  email:    {}", user.email);
        }
        UserCmd::List => {
            if store.users.is_empty() {
                println!("No users. Create one with: idp user create <username> --password <pw>");
            }
            for u in &store.users {
                println!("{}  {}  <{}>", u.id, u.username, u.email);
            }
        }
        UserCmd::Delete { username } => {
            let before = store.users.len();
            store.users.retain(|u| u.username != username);
            if store.users.len() == before {
                return Err(format!("no user named {username}").into());
            }
            store.save(path)?;
            println!("Deleted user {username}.");
        }
    }
    Ok(())
}

fn print_app(a: &Application) {
    println!("  name:          {}", a.name);
    println!("  client_id:     {}", a.client_id);
    println!("  client_secret: {}", a.client_secret);
    println!("  redirect_uris: {:?}", a.redirect_uris);
    println!("  logout_uris:   {:?}", a.post_logout_redirect_uris);
    println!("  scopes:        {}", a.scopes.join(" "));
}

fn info_command(store: &Store, client_id: Option<String>, as_json: bool) {
    let issuer = store.issuer();
    let apps: Vec<&Application> = match &client_id {
        Some(cid) => store.find_app(cid).into_iter().collect(),
        None => store.applications.iter().collect(),
    };

    if as_json {
        let value = serde_json::json!({
            "issuer": issuer,
            "discovery_url": format!("{issuer}/.well-known/openid-configuration"),
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "userinfo_endpoint": format!("{issuer}/userinfo"),
            "jwks_uri": format!("{issuer}/jwks"),
            "end_session_endpoint": format!("{issuer}/logout"),
            "applications": apps,
        });
        println!("{}", serde_json::to_string_pretty(&value).unwrap());
        return;
    }

    println!("OpenID Connect provider settings");
    println!("================================\n");
    println!("issuer                  {issuer}");
    println!("discovery_url           {issuer}/.well-known/openid-configuration");
    println!("authorization_endpoint  {issuer}/authorize");
    println!("token_endpoint          {issuer}/token");
    println!("userinfo_endpoint       {issuer}/userinfo");
    println!("jwks_uri                {issuer}/jwks");
    println!("end_session_endpoint    {issuer}/logout");
    println!("id_token signing alg    RS256");

    if apps.is_empty() {
        println!("\nNo applications registered. Create one with:");
        println!("  idp app create \"My App\" --redirect-uri http://localhost:3000/callback");
        return;
    }

    for a in apps {
        println!("\nApplication: {}", a.name);
        println!("--------------------------------");
        println!("client_id      {}", a.client_id);
        println!("client_secret  {}", a.client_secret);
        println!("scopes         {}", a.scopes.join(" "));
        if a.redirect_uris.is_empty() {
            println!("redirect_uris  (any — none registered)");
        } else {
            for r in &a.redirect_uris {
                println!("redirect_uri   {r}");
            }
        }
    }
}
