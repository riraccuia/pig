# JWT Signing Tool

A command-line tool for generating JWT tokens with RSA or ED25519 signatures. The tool provides both interactive key pair generation (with optional file storage) and token signing capabilities.

## Features

- Interactive key pair generation (RSA and ED25519)
- Optional key storage (in-memory or file-based)
- Support for RSA (RS256, RS384, RS512) and ED25519 (EdDSA) signatures
- Expiration time configuration
- Supports standard JWT claims
- Command-line flags for automation

## Usage

```bash
# Interactively generate keys and sign a token
./signtool

# Use an existing key to sign a new token interactively
./signtool -key /path/to/private.key

# Generate and save a new key pair to file and then sign a token with it interactively
./signtool -key ./new/key/path.pem

# Sign a token with a new ED25519 key that will be generated interactively
./signtool -alg EdDSA -exp 24h

# Sign a token unattended with an existing key
./signtool -key /path/to/private.key -alg EdDSA -exp 24h -iss admin@example.com -sub user@example.com -u
```

### Command Line Flags

- `-key`: Path to private key file (optional, will generate new key if not provided)
- `-alg`: Signing algorithm (RS256, RS384, RS512, EdDSA)
- `-exp`: Token expiration (e.g., 15m, 2h, 24h)
- `-iss`: Issuer (iss) claim
- `-sub`: Subject (sub) claim
- `-u`: Run unattended. All other flags are required.

## Key Generation

The tool provides an interactive key generation process when:
- No key file is specified
- The specified key file doesn't exist
- The existing key file is invalid

### Key Generation Process

1. **Key Type Selection**
```
   Available key types:
   1. RSA    (Supports RS256, RS384, RS512)
   2. ED25519 (Supports EdDSA)
```

2. **Key Parameters**
   - For RSA:
     - Minimum size: 2048 bits
     - Maximum size: 8192 bits
   
   - For ED25519:
     - No additional parameters needed (fixed key size)

3. **Storage Option**
   ```
   Do you want to save the generated key pair to files? (y/N):
   ```
   - If yes:
     ```
     Enter path to save private key (default: ./keys/private.pem):
     ```
     - Default directory: `./keys/`
     - Creates directory structure if needed
     - Generates two files:
       - `private.pem`: Private key (0600 permissions)
       - `public.pem`: Public key (0644 permissions)
     - Prompts for confirmation before overwriting existing files
   
   - If no:
     - Keeps keys in memory only
     - Displays public key in PEM format for saving
     - Private key is not displayed
     - Keys are discarded after token generation

### Key File Formats

#### RSA Keys
- Private key: PKCS1 or PKCS8 format
```
-----BEGIN RSA PRIVATE KEY-----
...
-----END RSA PRIVATE KEY-----
```

- Public key: PKIX format
```
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

#### ED25519 Keys
- Private key: PKCS8 format
```
-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
```

- Public key: PKIX format
```
-----BEGIN PUBLIC KEY-----
...
-----END PUBLIC KEY-----
```

## Token Generation

After key generation/selection, the tool will prompt for JWT claims if not already provided via flags:

1. **Required Claims**
   - `iss` (Issuer)
   - `sub` (Subject)
   - `exp` (Expiration Time)

2. **Optional Claims**
   - `aud` (Audience, supports multiple values)
   - `nbf` (Not Before) - defaults to current time
   - `iat` (Issued At) - automatically set to current time

## Integration with pig

Generate a token and use it with pig:
```bash
# Using existing key
./pig -c server:8080 -T "$(./signtool -key private.pem -alg RS256 -exp 24h -iss admin@pig -sub user@pig)"
```