# idp — mock OpenID Connect provider

A tiny CLI that runs a fake OIDC Identity Provider for local testing. Register
applications and users from the command line, start the server, and point any
real OIDC client at it.

> ⚠️ **Testing only.** Passwords are stored in plaintext, "quick sign-in" skips
> the password entirely, and the RSA key lives in a JSON file. Never use this
> with real credentials or expose it to a network.

## Build

```sh
cargo build --release
# binary: ./target/release/idp   (examples below use `idp`)
```

## Quick start

```sh
# 1. register an application (a client)
idp app create "My App" --redirect-uri http://localhost:3000/callback

# 2. create a user
idp user create alice --password s3cret --email alice@example.com --name "Alice A" --email-verified

# 3. start the server (default port 4444)
idp serve --port 4444

# 4. in another shell: dump everything needed to configure the external app
idp info
```

All state lives in `idp-data.json` in the current directory (override with
`--data <path>` or the `IDP_DATA` env var).

## Commands

| Command | Description |
| --- | --- |
| `idp app create <name> [--redirect-uri URL]... [--logout-uri URL]... [--scope S]...` | Register a client; prints `client_id` / `client_secret`. |
| `idp app list` / `app show <client_id>` / `app delete <client_id>` | Manage clients. |
| `idp user create <username> [--password P] [--email E] [--name N] [--given-name] [--family-name] [--email-verified] [--sub ID]` | Create a user. |
| `idp user list` / `user delete <username>` | Manage users. |
| `idp serve [--port N] [--issuer URL]` | Start the OIDC server. Flags persist to the data file. |
| `idp info [--client-id ID] [--json]` | Print issuer, endpoints, and client settings. |

If an application registers **no** redirect URIs, any `redirect_uri` is accepted
(convenient for quick experiments).

## What the server implements

Endpoints (relative to the issuer, e.g. `http://localhost:4444`):

- `GET  /.well-known/openid-configuration` — discovery document
- `GET  /authorize` — login page → issues an authorization code
- `POST /token` — `authorization_code`, `refresh_token`, `client_credentials`
- `GET/POST /userinfo` — claims for a bearer access token
- `GET  /jwks` — RSA public key (RS256)
- `GET  /logout` — end-session endpoint

Supported: Authorization Code flow, **PKCE** (`S256`/`plain`), `state`, `nonce`,
client auth via `client_secret_basic` or `client_secret_post`, refresh tokens
(request the `offline_access` scope), and arbitrary extra claims per user (edit
the `claims` object in the data file). Tokens are RS256 JWTs.

## Login during the flow

When your app redirects the browser to `/authorize`, the mock shows a minimal
sign-in page. You can either type the username + password, or use a one-click
**"Sign in as …"** button (no password — handy for scripted/automated tests).

## Configuring a typical OIDC client

```
Issuer / Discovery URL : http://localhost:4444/.well-known/openid-configuration
Client ID / Secret     : from `idp app create` (or `idp info`)
Redirect URI           : the one you registered
Scopes                 : openid profile email offline_access
```
