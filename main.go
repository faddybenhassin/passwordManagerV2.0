package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

type Vault struct {
	Salt          string
	Nonce         string
	EncryptedData string
}
type Data struct {
	Entries []Entry
}

type Entry struct {
	Domain    string
	UserName  string
	Password  string
	CreatedAt time.Time
}

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	keyLen       = 32 // AES-256
	nonceSize    = 12 // AES-GCM standard
	saltSize     = 16
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: manager <init|add|list> [args]")
		os.Exit(1)
	}

	cmd := os.Args[1]
	switch cmd {
	case "init":
		if len(os.Args) < 3 {
			fmt.Println("usage: manager init <vault-file-path>")
			os.Exit(1)
		}
		path := os.Args[2]+".json"
		initVault(path)
	case "add":
		if len(os.Args) < 6 {
			fmt.Println("usage: manager add <vault-file-path> <domain> <username> <password>")
			os.Exit(1)
		}
		path := os.Args[2]
		domain := os.Args[3]
		username := os.Args[4]
		password := os.Args[5]
		addEntry(path, domain, username, password)
	case "list":
		if len(os.Args) < 3 {
			fmt.Println("usage: manager list <vault-file-path>")
			os.Exit(1)
		}
		path := os.Args[2]
		listEntries(path)
	default:
		fmt.Println("unknown command")
	}
}

func getPassword() string {
	fmt.Print("Enter master password: ")
	var masterPassword string
	// simple read from stdin - not hiding input for brevity; on real apps use a proper password prompt
	fmt.Scanln(&masterPassword)
	return strings.TrimSpace(masterPassword)
}

func initVault(path string) {
	masterPassword := getPassword()

	Data := Data{Entries: []Entry{}}

	DataJSON, _ := json.Marshal(Data)
	Vault, err := encryptWithPassword(DataJSON, masterPassword)
	if err != nil {
		fmt.Println("error encrypting vault:", err)
		os.Exit(1)
	}
	vaultJSON, _ := json.MarshalIndent(Vault, "", " ")
	err = os.WriteFile(path, vaultJSON, 0600)
	if err != nil {
		fmt.Println("error writing vault:", err)
		os.Exit(1)
	}
	fmt.Println("vault created at", path)
}

func addEntry(path string, domain string, username string, password string) {
	masterPassword := getPassword()
	vault, err := loadVault(path)
	if err != nil {
		fmt.Println("error loading vault:", err)
		os.Exit(1)
	}
	dataJSON, err := decryptWithPassword(vault, masterPassword)
	if err != nil {
		fmt.Println("wrong password or corrupt vault")
		os.Exit(1)
	}
	var data Data
	err = json.Unmarshal(dataJSON, &data)
	if err != nil {
		fmt.Println("bad data format:", err)
		os.Exit(1)
	}
	data.Entries = append(data.Entries, Entry{Domain: domain, UserName: username, Password: password})
	newDataJson, _ := json.Marshal(data)
	newVault, err := encryptWithPassword(newDataJson, masterPassword)
	if err != nil {
		fmt.Println("error encrypting:", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(newVault, "", " ")
	err = os.WriteFile(path, out, 0600)
	if err != nil {
		fmt.Println("error writing vault:", err)
		os.Exit(1)
	}
	fmt.Println("entry added")
}

func listEntries(path string) {
	masterPassword := getPassword()
	vault, err := loadVault(path)
	if err != nil {
		fmt.Println("error loading vault:", err)
		os.Exit(1)
	}

	dataJSON, err := decryptWithPassword(vault, masterPassword)
	if err != nil {
		fmt.Println("wrong password or corrupt vault")
		os.Exit(1)
	}
	var data Data
	err = json.Unmarshal(dataJSON, &data)

	if err != nil {
		fmt.Println("bad data format:", err)
		os.Exit(1)
	}
	for _, entry := range data.Entries {
		fmt.Printf("Domain: %s username: %s password: %s\n", entry.Domain, entry.UserName, entry.Password)
	}

}

func loadVault(path string) (*Vault, error) {
	vaultJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vault Vault
	err = json.Unmarshal(vaultJSON, &vault)
	if err != nil {
		return nil, err
	}
	return &vault, nil
}

func encryptWithPassword(plaintext []byte, password string) (*Vault, error) {
	// generate salt
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	derivedKey := deriveKey([]byte(password), salt)
	defer zeroBytes(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)

	vault := &Vault{
		Salt:          base64.RawStdEncoding.EncodeToString(salt),
		Nonce:         base64.RawStdEncoding.EncodeToString(nonce),
		EncryptedData: base64.RawStdEncoding.EncodeToString(ciphertext),
	}
	return vault, nil
}
func decryptWithPassword(vault *Vault, password string) ([]byte, error) {
	salt, err := base64.RawStdEncoding.DecodeString(vault.Salt)
	if err != nil {
		return nil, err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(vault.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(vault.EncryptedData)
	if err != nil {
		return nil, err
	}

	derivedKey := deriveKey([]byte(password), salt)
	defer zeroBytes(derivedKey)

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	data, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// authentication failed -> wrong password or tampering
		return nil, errors.New("decryption failed")
	}
	return data, nil
}

func deriveKey(password, salt []byte) []byte {
	// Argon2id derivation
	derivedKey := argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, keyLen)
	return derivedKey
}

func zeroBytes(byteSlice []byte) {
	for i := range byteSlice {
		byteSlice[i] = 0
	}
}
