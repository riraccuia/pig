# OIDC authentication

OIDC authentication can be activated via config file only. There are no CLI flags for it today. They may be added later.

Set `auth.type` to `oidc`. Field names are in the [config reference](../config.md#oidcauth) under `auth.oidc`.

For providers that only issue OAuth access tokens (for example GitHub), use [OAuth authentication](oauth.md) instead.

## What you need

You need the usual OIDC values: issuer URL, client ID, and a client secret. Register a loopback redirect URI with the provider.

Generate a starting config with `-to-cfg json` or `-to-cfg toml`, then add the `auth` block in the desired tunnel section.

## Listener

Listeners check issuer, audience, signature, and expiration on the framed `id_token`. Set `issuer_url` and `client_id`.
You can set `expected_audience` to check `aud` against a specific value.

```json
"auth": {
  "type": "oidc",
  "oidc": {
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-client-id"
  }
}
```

## Connector

The connect node runs the authorization code flow in the browser, then sends the `id_token` to the listener. If the token is still valid, or can be refreshed, pig reuses it and does not open the browser again.

The authorization request includes a `nonce`. After the code flow, pig requires that value in the `id_token` before sending it.

```json
"auth": {
  "type": "oidc",
  "oidc": {
    "issuer_url": "https://accounts.google.com",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret"
  }
}
```

The PKCE flow is used by default.

When `redirect_url` is empty, pig binds an ephemeral port on `127.0.0.1` and uses `http://127.0.0.1:<port>/oauth2/callback`. If you set `redirect_url`, the host must be `127.0.0.1` or `localhost` and the port must be explicit. The URI must match what you registered at the provider.

## Optional settings

- `scopes`: defaults to `openid`, `profile`, `email`. If you set scopes yourself, `openid` is added when missing
- `redirect_path`: callback path when `redirect_url` is empty. Defaults to `/oauth2/callback`
- `skip_open_browser`: do not open a browser. The error includes the URL to open by hand
- `callback_timeout_seconds`: how long to wait for the redirect. Defaults to `180`
- `clock_skew_seconds`: leeway when checking `id_token` expiration on the listener and when reusing a cached token. Defaults to `30`
- `disable_pkce`: turn PKCE off. Not recommended

## Claim matchers

`claim_matchers` adds extra checks after the `id_token` is accepted. Each key is a claim name.

- A string is a regular expression (use `^...$` for a full-string match)
- An array of strings: the claim must equal one of the values exactly
