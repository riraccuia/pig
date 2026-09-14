# OAuth authentication

OAuth authentication can be activated via config file only. There are no CLI flags for it today. They may be added later.

Set `auth.type` to `oauth`. Field names are in the [config reference](../config.md#authconfig) under `auth.oauth`.

Some providers return opaque access tokens but no discoverable introspection endpoint.
Pig includes helpers for popular non standard providers, so you still use the same `auth.oauth` fields.
See [Using GitHub](#github) and [Using Google](#google).

## What you need

You need the usual OAuth values: issuer URL, client ID, and a client secret. Register a loopback redirect URI with the provider.

Generate a starting config with `-to-cfg json` or `-to-cfg toml`, then add the `auth` block in the desired tunnel section.

## Listener

Listeners verify the framed OAuth access token, in this order:

1. A built-in opaque helper, when the issuer is one pig supports (GitHub or Google)
2. Otherwise JWT verification, when the access token looks like a JWT and discovery provides `jwks_uri` (issuer, audience, signature, and expiration)
3. Otherwise pig rejects the token

If the provider returns an opaque access token (not a valid JWT) and pig has no helper for that issuer, the listener cannot validate the token. There is also no JWT payload to parse for `claim_matchers`.

Set `issuer_url` and `client_id`.
You can set `expected_audience` to check `aud` against a specific value when verifying a JWT access token.

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "issuer_url": "https://github.com/login/oauth",
    "client_id": "your-client-id"
  }
}
```

## Connector

The connect node runs the authorization code flow in the browser, then sends the access token to the listener. If the token is still valid, or can be refreshed, pig reuses it and does not open the browser again.

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "issuer_url": "https://github.com/login/oauth",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scopes": ["user:email"]
  }
}
```

The PKCE flow is used by default.

When `redirect_url` is empty, pig binds an ephemeral port on `127.0.0.1` and uses `http://127.0.0.1:<port>/oauth2/callback`. If you set `redirect_url`, the host must be `127.0.0.1` or `localhost` and the port must be explicit. The URI must match what you registered at the provider.

## Optional settings

- `scopes`: authorization request scopes. If empty, no scope parameter is sent
- `redirect_path`: callback path when `redirect_url` is empty. Defaults to `/oauth2/callback`
- `skip_open_browser`: do not open a browser. The error includes the URL to open by hand
- `callback_timeout_seconds`: how long to wait for the redirect. Defaults to `180`
- `clock_skew_seconds`: leeway when checking JWT access token expiration on the listener. Defaults to `30`
- `disable_pkce`: turn PKCE off. Not recommended

## Claim matchers

`claim_matchers` adds extra checks after the token is accepted. Each key is a claim name.

- A string is a regular expression (use `^...$` for a full-string match)
- An array of strings: the claim must equal one of the values exactly

For JWT access tokens, matchers run against JWT claims. For opaque tokens, only claims listed under the provider sections below are available. If there is no JWT and no helper for the issuer, there are no claims to match.

## Using GitHub

GitHub’s OAuth authorization server issues an opaque access token, not a JWT. Pig validates the token using the GitHub API.

First create an OAuth App: GitHub → Settings → Developer settings → OAuth Apps → New OAuth App.

Give it a name and a homepage URL. Set Redirect URI to `http://127.0.0.1/oauth2/callback` and tick "Allow wildcard matching".
Copy the client ID and generate a client secret.

On the connector, set the `user:email` scope so GitHub issues a token that can read email addresses. The listener always calls `GET /user/emails` and requires a verified primary email, even when `claim_matchers` is empty.

Claims for `claim_matchers` are not JWT claims. They are resolved from GitHub’s authenticated-user REST API after the access token is accepted:

| Claim | Source |
| --- | --- |
| `email` | Verified addresses from `GET https://api.github.com/user/emails` |
| `login` | `GET https://api.github.com/user` |
| `name` | `GET https://api.github.com/user` |
| `id` | `GET https://api.github.com/user` (numeric user id as a string) |
| `sub` | Same as `id` |

> [!WARNING]
> The listener does not check `client_id` (or any OAuth app identity) against the GitHub API.
> Any GitHub access token that can call those endpoints and has a verified primary email is accepted.
> Restrict access with `claim_matchers` (for example `email` or `login`) if that matters for your deployment.

Listener:

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "client_id": "your-client-id",
    "issuer_url": "https://github.com/login/oauth",
    "claim_matchers": {
      "email": ["user@email.example"]
    }
  }
}
```

Connector:

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "issuer_url": "https://github.com/login/oauth",
    "client_id": "your-client-id",
    "client_secret": "your-secret",
    "scopes": ["user:email"]
  }
}
```

## Using Google

Google’s OAuth access tokens are opaque. Pig validates the token using Google’s tokeninfo endpoint (`https://oauth2.googleapis.com/tokeninfo`).

Create an OAuth client in Google Cloud Console (APIs & Services → Credentials). Use an application type that allows a loopback redirect. Register a redirect URI such as `http://127.0.0.1/oauth2/callback` (or your fixed loopback URL). Copy the client ID and client secret.

If you set `client_id` or `expected_audience`, the listener requires tokeninfo `aud` or `azp` to match that value.

Claims available for `claim_matchers` (from tokeninfo):

| Claim | Notes |
| --- | --- |
| `email` | Only when present and `email_verified` is true |
| `email_verified` | e.g. `"true"` |
| `sub` | Google user id |
| `aud` | Audience |
| `azp` | Authorized party |
| `scope` | Space-separated scopes |

Request an email-capable scope on the connector if you want to match on `email` (for example `email` or `https://www.googleapis.com/auth/userinfo.email`).

Listener:

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-client-id.apps.googleusercontent.com",
    "claim_matchers": {
      "email": ["user@email.example"]
    }
  }
}
```

Connector:

```json
"auth": {
  "type": "oauth",
  "oauth": {
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-client-id.apps.googleusercontent.com",
    "client_secret": "your-secret",
    "scopes": ["email"]
  }
}
```
