# JWT Signing Tool

A command-line tool for generating JWT tokens with RSA or ED25519 signatures. The tool provides both interactive key pair generation (with optional file storage) and token signing capabilities.

## Features

- Interactive key pair generation (RSA and ED25519)
- Optional key storage (in-memory or file-based)
- Support for RSA (RS256, RS384, RS512) and ED25519 (EdDSA) signatures
- Flexible expiration time configuration
- Full support for standard JWT claims
- Command-line flags for automation

## Usage

```bash
# Interactive mode (will generate keys if needed)
./signtool

# Use existing key
./signtool -key /path/to/private.key -alg RS256 -exp 24h

# Generate new key pair at specific location
./signtool -key ./new/key/path.pem
```

### Command Line Flags

- `-key`: Path to private key file (optional, will generate new key if not provided)
- `-alg`: Signing algorithm (RS256, RS384, RS512, EdDSA)
- `-exp`: Token expiration (e.g., 15m, 2h, 24h)

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
   
   Select key type (1-2):
   ```

2. **Key Parameters**
   - For RSA:
     ```
     Enter RSA key size (2048-8192 bits):
     ```
     - Minimum size: 2048 bits (recommended for general use)
     - Maximum size: 8192 bits (for high security requirements)
   
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
     - Private key is never displayed
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

After key generation/selection, the tool will prompt for JWT claims:

1. **Required Claims**
   - `iss` (Issuer)
   - `sub` (Subject)
   - `aud` (Audience, supports multiple values)
   - `exp` (Expiration Time)

2. **Optional Claims**
   - `nbf` (Not Before) - defaults to current time
   - `iat` (Issued At) - automatically set to current time

## Examples

1. Generate new RSA key pair in memory:
```bash
./signtool
# Tool will guide you through:
# 1. Key type selection (RSA)
# 2. Key size selection (e.g., 2048)
# 3. Choose 'N' when asked about saving
# 4. Copy displayed public key
# 5. Enter token parameters
```

2. Generate ED25519 key pair with file storage:
```bash
./signtool -key ./my-keys/ed25519.pem
# Select ED25519 when prompted
# Choose 'Y' when asked about saving
```

3. Use existing key with specific algorithm:
```bash
./signtool -key private.pem -alg RS256
```

4. Generate token with custom expiration:
```bash
./signtool -key ed25519.pem -alg EdDSA -exp 1h
```

## Integration with pig

Generate a token and use it with pig:
```bash
# Using existing key
./pig -c server:8080 -jwt-tok "$(./signtool -key private.pem -alg RS256 -exp 24h)"

# Generate new key in memory and use token
./pig -c server:8080 -jwt-tok "$(./signtool)"
# Make sure to save the displayed public key for server configuration
```

## Security Considerations

1. **Key Storage**
   - File-based storage:
     - Private keys are saved with 0600 permissions (user read/write only)
     - Public keys are saved with 0644 permissions (world-readable)
     - Use secure locations for key storage
     - Back up private keys securely
   - In-memory storage:
     - More secure for temporary use
     - Keys are discarded after token generation
     - Only public key is displayed
     - Suitable for one-time token generation

2. **Key Selection**
   - RSA: 
     - Minimum 2048 bits for general use
     - 4096 bits recommended for high security
     - Larger keys provide more security but slower operations
   - ED25519:
     - Fixed key size
     - Provides strong security with better performance
     - Recommended for new applications

3. **Token Lifetime**
   - Use appropriate expiration times
   - Consider using the `nbf` claim for delayed validity
   - Short-lived tokens reduce security risks 