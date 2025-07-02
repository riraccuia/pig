package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

var (
	keyFile    string
	algorithm  string
	expiration string
)

const (
	helpText = `
JWT Token Generation Tool

This tool generates JWT tokens signed with either RSA or ED25519 keys.
Supported algorithms: RS256, RS384, RS512, EdDSA

If no private key is provided, the tool will help you generate a new key pair.

Expiration format examples:
  15m  - 15 minutes
  2h   - 2 hours
  24h  - 1 day
  2d   - 2 days
`

	minRSAKeySize = 2048
	maxRSAKeySize = 8192
)

type keyType int

const (
	keyTypeRSA keyType = iota
	keyTypeED25519
)

func (kt keyType) String() string {
	switch kt {
	case keyTypeRSA:
		return "RSA"
	case keyTypeED25519:
		return "ED25519"
	default:
		return "Unknown"
	}
}

func init() {
	flag.StringVar(&keyFile, "key", "", "Path to private key file (will be generated if it doesn't exist)")
	flag.StringVar(&algorithm, "alg", "", "Signing algorithm (RS256, RS384, RS512, EdDSA)")
	flag.StringVar(&expiration, "exp", "", "Token expiration (e.g., 15m, 2h, 24h)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", helpText)
		flag.PrintDefaults()
	}
}

type tokenParams struct {
	issuer    string
	subject   string
	audience  []string
	expiresAt time.Time
	notBefore time.Time
	issuedAt  time.Time
}

func readLine(prompt string) string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, _ := reader.ReadString('\n')
	return strings.TrimSpace(text)
}

func readMultiLine(prompt string) []string {
	fmt.Println(prompt)
	fmt.Println("(Enter one per line, empty line to finish)")

	var lines []string
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "" {
			break
		}
		lines = append(lines, text)
	}
	return lines
}

func parseExpiration(exp string) (time.Duration, error) {
	// Check for day format (e.g., "10d")
	if len(exp) > 0 && exp[len(exp)-1] == 'd' {
		// Extract the number part
		numStr := exp[:len(exp)-1]
		days, err := strconv.Atoi(numStr)
		if err != nil {
			return 0, fmt.Errorf("invalid day format: %w", err)
		}
		// Convert days to hours (24 hours per day)
		exp = fmt.Sprintf("%dh", days*24)
	}

	duration, err := time.ParseDuration(exp)
	if err != nil {
		return 0, fmt.Errorf("invalid expiration format: %w", err)
	}
	if duration <= 0 {
		return 0, fmt.Errorf("expiration must be positive")
	}
	return duration, nil
}

func promptForExpiration() time.Duration {
	for {
		exp := readLine("Enter token expiration (e.g., 15m, 2h, 24h, 2d): ")
		duration, err := parseExpiration(exp)
		if err == nil {
			return duration
		}
		fmt.Printf("Error: %v\n", err)
	}
}

func promptForAlgorithm() string {
	validAlgs := map[string]bool{
		"RS256": true,
		"RS384": true,
		"RS512": true,
		"EdDSA": true,
	}

	for {
		alg := readLine("Enter signing algorithm (RS256, RS384, RS512, EdDSA): ")
		if validAlgs[alg] {
			return alg
		}
		fmt.Println("Error: invalid algorithm")
	}
}

func loadPrivateKey(path string) (interface{}, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PRIVATE KEY", "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS1 for RSA keys
			key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

func getSigningMethod(alg string, key interface{}) (jwt.SigningMethod, error) {
	switch alg {
	case "RS256":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("key type does not match algorithm RS256")
		}
		return jwt.SigningMethodRS256, nil
	case "RS384":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("key type does not match algorithm RS384")
		}
		return jwt.SigningMethodRS384, nil
	case "RS512":
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("key type does not match algorithm RS512")
		}
		return jwt.SigningMethodRS512, nil
	case "EdDSA":
		if _, ok := key.(ed25519.PrivateKey); !ok {
			return nil, fmt.Errorf("key type does not match algorithm EdDSA")
		}
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func promptForTokenParams() *tokenParams {
	now := time.Now()

	params := &tokenParams{
		issuedAt:  now,
		notBefore: now,
	}

	params.issuer = readLine("Enter issuer (iss): ")
	params.subject = readLine("Enter subject (sub): ")
	params.audience = readMultiLine("Enter audience values (aud)")

	duration := promptForExpiration()
	params.expiresAt = now.Add(duration)

	nbf := readLine("Enter not-before offset in minutes (0 for now): ")
	if offset, err := strconv.Atoi(nbf); err == nil && offset > 0 {
		params.notBefore = now.Add(time.Duration(offset) * time.Minute)
	}

	return params
}

func generateToken(key interface{}, method jwt.SigningMethod, params *tokenParams) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    params.issuer,
		Subject:   params.subject,
		Audience:  params.audience,
		ExpiresAt: jwt.NewNumericDate(params.expiresAt),
		NotBefore: jwt.NewNumericDate(params.notBefore),
		IssuedAt:  jwt.NewNumericDate(params.issuedAt),
	}

	wk, err := jwk.Import(key)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK: %w", err)
	}

	err = jwk.AssignKeyID(wk)
	if err != nil {
		return "", fmt.Errorf("failed to assign key ID: %w", err)
	}

	kid, ok := wk.KeyID()
	if !ok {
		return "", fmt.Errorf("key ID is not set")
	}

	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid

	return token.SignedString(key)
}

func promptForKeyType() keyType {
	fmt.Println("\nAvailable key types:")
	fmt.Println("1. RSA    (Supports RS256, RS384, RS512)")
	fmt.Println("2. ED25519 (Supports EdDSA)")

	for {
		choice := readLine("\nSelect key type (1-2): ")
		switch choice {
		case "1":
			return keyTypeRSA
		case "2":
			return keyTypeED25519
		default:
			fmt.Println("Invalid choice. Please select 1 or 2.")
		}
	}
}

func promptForRSAKeySize() int {
	for {
		sizeStr := readLine(fmt.Sprintf("Enter RSA key size (%d-%d bits): ", minRSAKeySize, maxRSAKeySize))
		size, err := strconv.Atoi(sizeStr)
		if err != nil || size < minRSAKeySize || size > maxRSAKeySize {
			fmt.Printf("Invalid key size. Must be between %d and %d bits.\n", minRSAKeySize, maxRSAKeySize)
			continue
		}
		return size
	}
}

func promptForKeyPath() string {
	defaultDir := "keys"
	defaultPath := filepath.Join(defaultDir, "private.pem")

	for {
		path := readLine(fmt.Sprintf("Enter path to save private key (default: %s): ", defaultPath))
		if path == "" {
			path = defaultPath
			// Only create the default directory if using the default path
			if err := os.MkdirAll(defaultDir, 0755); err != nil {
				fmt.Printf("Failed to create directory %s: %v\nUsing current directory instead.\n", defaultDir, err)
				path = "private.pem"
			}
		}

		// Check if file already exists
		if _, err := os.Stat(path); err == nil {
			confirm := readLine(fmt.Sprintf("File %s already exists. Overwrite? (y/N): ", path))
			if !strings.EqualFold(confirm, "y") {
				continue
			}
		}

		// Ensure the directory exists for the chosen path
		dir := filepath.Dir(path)
		if dir != "." {
			if err := os.MkdirAll(dir, 0755); err != nil {
				fmt.Printf("Failed to create directory %s: %v\n", dir, err)
				continue
			}
		}

		return path
	}
}

func generateKeyPair(kt keyType, rsaKeySize int) (interface{}, interface{}, error) {
	switch kt {
	case keyTypeRSA:
		privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		return privateKey, &privateKey.PublicKey, nil

	case keyTypeED25519:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ED25519 key: %w", err)
		}
		return privateKey, publicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported key type: %s", kt)
	}
}

func saveKeyPair(privateKey, publicKey interface{}, privatePath string) error {
	// Derive public key path
	dir, _ := filepath.Split(privatePath)
	publicPath := filepath.Join(dir, "public.pem")

	// Encode and save private key
	var privateBlock *pem.Block
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		privateBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case ed25519.PrivateKey:
		var err error
		privateBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal ED25519 private key: %w", err)
		}
		privateBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}
	default:
		return fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	if err := os.WriteFile(privatePath, pem.EncodeToMemory(privateBlock), 0600); err != nil {
		return fmt.Errorf("failed to save private key: %w", err)
	}

	// Encode and save public key
	var publicBlock *pem.Block
	switch k := publicKey.(type) {
	case *rsa.PublicKey:
		publicBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal RSA public key: %w", err)
		}
		publicBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		}
	case ed25519.PublicKey:
		publicBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return fmt.Errorf("failed to marshal ED25519 public key: %w", err)
		}
		publicBlock = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		}
	default:
		return fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	if err := os.WriteFile(publicPath, pem.EncodeToMemory(publicBlock), 0644); err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	fmt.Printf("Key pair generated:\n  Private key: %s\n  Public key: %s\n\n", privatePath, publicPath)
	return nil
}

func promptForKeyStorage() bool {
	for {
		response := readLine("Do you want to save the generated key pair to files? (y/N): ")
		switch strings.ToLower(response) {
		case "y", "yes":
			return true
		case "", "n", "no":
			return false
		default:
			fmt.Println("Please answer 'y' for yes or 'n' for no")
		}
	}
}

func encodeKeyToPEM(key interface{}) ([]byte, error) {
	var block *pem.Block

	switch k := key.(type) {
	case *rsa.PublicKey:
		publicBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		}
	case ed25519.PublicKey:
		publicBytes, err := x509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ED25519 public key: %w", err)
		}
		block = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicBytes,
		}
	case *rsa.PrivateKey:
		// Try PKCS8 first, fall back to PKCS1 if that fails
		privateBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			// Fall back to PKCS1 for RSA keys
			privateBytes = x509.MarshalPKCS1PrivateKey(k)
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}
	case ed25519.PrivateKey:
		privateBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ED25519 private key: %w", err)
		}
		block = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateBytes,
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	return pem.EncodeToMemory(block), nil
}

func getOrGenerateKey(keyPath string) (interface{}, interface{}, error) {
	// Try to load existing key if path is provided
	if keyPath != "" {
		if key, err := loadPrivateKey(keyPath); err == nil {
			// Extract public key for RSA
			switch k := key.(type) {
			case *rsa.PrivateKey:
				return key, &k.PublicKey, nil
			case ed25519.PrivateKey:
				fmt.Println("Loaded ed25519 public key")
				return key, k.Public(), nil
			default:
				return nil, nil, fmt.Errorf("unsupported key type: %T", key)
			}
		}
	}

	// Key doesn't exist or wasn't specified, prompt for generation
	fmt.Println("\nNo valid private key found. Let's generate a new key pair.")

	// Get key type
	kt := promptForKeyType()

	// Get key size for RSA
	var rsaKeySize int
	if kt == keyTypeRSA {
		rsaKeySize = promptForRSAKeySize()
	}

	// Generate key pair
	privateKey, publicKey, err := generateKeyPair(kt, rsaKeySize)
	if err != nil {
		return nil, nil, err
	}

	// Ask if user wants to save the keys
	if promptForKeyStorage() {
		// Get save path if not provided
		savePath := keyPath
		if savePath == "" {
			savePath = promptForKeyPath()
		}

		// Save keys
		if err := saveKeyPair(privateKey, publicKey, savePath); err != nil {
			return nil, nil, err
		}

		return privateKey, publicKey, nil
	}

	// Display public key in PEM format
	pubPemBytes, err := encodeKeyToPEM(publicKey)
	if err != nil {
		fmt.Printf("Warning: Failed to encode public key: %v\n", err)
		return nil, nil, err
	}

	fmt.Printf("\nGenerated public key (save this for verification):\n%s\n", string(pubPemBytes))

	// Display private key in PEM format
	privPemBytes, err := encodeKeyToPEM(privateKey)
	if err != nil {
		fmt.Printf("Warning: Failed to encode private key: %v\n", err)
		return nil, nil, err
	}

	fmt.Printf("\nGenerated private key (save this for future use):\n%s\n", string(privPemBytes))

	return privateKey, publicKey, nil
}

func main() {
	flag.Parse()

	// Get or generate private key
	privateKey, _, err := getOrGenerateKey(keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error with private key: %v\n", err)
		os.Exit(1)
	}

	if algorithm == "" {
		algorithm = promptForAlgorithm()
	}

	method, err := getSigningMethod(algorithm, privateKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	params := promptForTokenParams()

	token, err := generateToken(privateKey, method, params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating token: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nGenerated JWT Token:\n%s\n", token)
}
