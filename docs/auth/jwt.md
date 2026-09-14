# JWT authentication

JWT enables stateless authentication.
The connect node presents a cryptographically signed token.
The listener node verifies it against a public key.

JWT tokens have a limited lifetime, which is set at generation time. 
You can send a token to a friend that expires in 1 day and then forget about it: there is nothing to revoke.

Pig supports the `RS256`, `RS384`, `RS512`, and `EdDSA` algorithms.
It checks the signature and expiration but does not require any particular claims.

## What you need

A key pair and a signed token. To create them, use [signtool](../../tools/signtool/README.md).

Set `-A jwt` on both sides.
Give the listen node the public key.
Give the connect node a token generated with the corresponding private key.

## Listener

Point `-jwk` at the public key, then start the listen node.

```bash
pig -l -s -a 0.0.0.0:443 -A jwt -jwk ./public.pem
```

## Connector

Set `PIG_TOKEN` to the token string, then start the connect node.

```bash
export PIG_TOKEN=$(./signtool -key private.pem -alg EdDSA -exp 1d -iss <issuer-name> -sub <subject-name> -u)
pig -c -s -a listen.example:443 -A jwt
```

Prefer `PIG_TOKEN` over `-T`. If the token lives in a `.env` file, source that file in your shell first. Pig does not load `.env` on its own.

## Config file

Use `-to-cfg json` to generate a config file.

```bash
pig -l -s -a 0.0.0.0:443 -A jwt -jwk ./public.pem -to-cfg json > listen.json
pig -config listen.json
```

JWT settings are in the tunnel `auth` block.

```json
"auth": {
  "type": "jwt",
  "jwt": {
    "public_key_source": "./public.pem",
    "token": ""
  }
}
```

Listen nodes need `public_key_source`. Connect nodes need `token`, or leave it empty and set `PIG_TOKEN`.

See the [config reference](../config.md) for the rest of the file. CLI flags: [listen](../cli-help/listen.md), [connect](../cli-help/connect.md).

## NAT traversal

The same `-A`, `-jwk`, and `PIG_TOKEN` options apply when you use `-id` instead of `-s`.

## Public key sources

`-jwk` and `public_key_source` accept:

- A PEM public key file
- A JWKS file (JSON that holds one or more public keys). The path must end in `.json`.
- An `http://` or `https://` URL that returns JWKS

## Common issues

Pig does not start when:

- The listen node has `-A jwt` (or `auth.type` `jwt`) without a public key source
- The connect node has `-A jwt` without a token in `PIG_TOKEN`, `-T`, or `auth.jwt.token`

Listeners reject the token if it is expired, signed with a different key, or uses an unsupported algorithm.