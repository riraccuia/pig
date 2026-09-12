// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signaling

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// Encrypt method to encrypt text using a passkey with AES-GCM.
func Encrypt(plaintext, passkey []byte) ([]byte, error) {
	// Convert the passkey to a 32-byte key
	if len(passkey) < 32 {
		// If the passkey is shorter than 32 bytes, pad it
		passkey = append(passkey, make([]byte, 32-len(passkey))...)
	}

	if len(passkey) > 32 {
		// If the passkey is longer than 32 bytes, truncate it
		passkey = passkey[:32]
	}

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(passkey)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Convert the plaintext to bytes
	plaintextBytes := []byte(plaintext)

	// Encrypt the plaintext using AES-GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintextBytes, nil)

	// Combine the nonce and ciphertext
	combined := append(nonce, ciphertext...)

	// Return the encrypted data
	return combined, nil
}

// Decrypt method to decrypt text using a passkey with AES-GCM.
func Decrypt(encryptedText, passkey []byte) ([]byte, error) {
	// Convert the passkey to a 32-byte key
	if len(passkey) < 32 {
		// If the passkey is shorter than 32 bytes, pad it
		passkey = append(passkey, make([]byte, 32-len(passkey))...)
	}

	if len(passkey) > 32 {
		// If the passkey is longer than 32 bytes, truncate it
		passkey = passkey[:32]
	}

	// Create a new AES cipher using the key
	block, err := aes.NewCipher(passkey)
	if err != nil {
		return nil, err
	}

	// Extract the nonce and ciphertext from the combined data
	if len(encryptedText) < 12 {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := encryptedText[:12], encryptedText[12:]

	// Decrypt the ciphertext using AES-GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	// Return the decrypted data as a string
	return plaintextBytes, nil
}
