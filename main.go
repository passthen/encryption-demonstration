package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	var userName string
	var masterPassword string
	var iterations int
	var masterKey []byte

	fmt.Print("Please enter your username.\n > ")
	fmt.Scanf("%s", &userName)
	if !isValidUsername(userName) {
		fmt.Println("Invalid user name only supports numbers, English letters, dots and underscores.")
		os.Exit(0)
	}
	fmt.Print("Please enter your master password.\n > ")
	fmt.Scanf("%s", &masterPassword)
	fmt.Print("Please enter your custom iterations.\n > ")
	fmt.Scanf("%d", &iterations)
	timeStart := time.Now()
	masterKey = KDF(userName, masterPassword, iterations, 32)
	fmt.Println("Total generate key time: ", time.Since(timeStart))
	fmt.Println("Here is your master key:")
	fmt.Println(masterKey)

	authenticationKey := KDFToServer(userName, masterKey)
	fmt.Println("Your key that store in server to authentication:\n" + string(authenticationKey))

	iv := generateIV()
	ciphertext := Ase256(masterPassword, masterKey, iv, aes.BlockSize)
	fmt.Printf("Encrypted: %s\n", ciphertext)

	decryptedData := Ase256Decode(ciphertext, masterKey, iv)
	fmt.Printf("Decrypted: %s\n", string(decryptedData))

}

func isValidUsername(username string) bool {
	usernameRegex := regexp.MustCompile(`^[a-zA-Z0-9_.]+$`)

	if len(username) < 3 || len(username) > 20 {
		return false
	}

	return usernameRegex.MatchString(username)
}

func KDF(payload, slat string, iterations, length int) []byte {
	time := uint32(iterations)
	memory := uint32(64 * 1024)
	threads := uint8(4)
	keyLength := uint32(length)

	key := argon2.IDKey([]byte(payload), []byte(slat), time, memory, threads, keyLength)
	return key
}

func KDFToServer(masterPassword string, masterKey []byte) []byte {
	encryptPayload := KDF(masterPassword, string(masterKey), 1, 72)

	hashedPassword, err := bcrypt.GenerateFromPassword(encryptPayload, 14)
	if err != nil {
		fmt.Println(err)
		return []byte("")
	}
	return hashedPassword
}

func generateIV() []byte {
	iv := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(rand.Reader, iv)
	if err != nil {
		panic(err)
	}
	return iv
}

func Ase256(plaintext string, key, iv []byte, blockSize int) string {
    bKey := []byte(key)
    bIV := []byte(iv)
    bPlaintext := PKCS5Padding([]byte(plaintext), blockSize, len(plaintext))
    block, err := aes.NewCipher(bKey)
    if err != nil {
        panic(err)
    }
    ciphertext := make([]byte, len(bPlaintext))
    mode := cipher.NewCBCEncrypter(block, bIV)
    mode.CryptBlocks(ciphertext, bPlaintext)
    return hex.EncodeToString(ciphertext)
}
func PKCS5UnPadding(src []byte) []byte {
    length := len(src)
    unpadding := int(src[length-1])
    return src[:(length - unpadding)]
}
func PKCS5Padding(ciphertext []byte, blockSize int, after int) []byte {
    padding := (blockSize - len(ciphertext)%blockSize)
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(ciphertext, padtext...)
}
func Ase256Decode(cipherText string, encKey, iv []byte) (decryptedString string) {
    bKey := []byte(encKey)
    bIV := []byte(iv)
    cipherTextDecoded, err := hex.DecodeString(cipherText)
    if err != nil {
        panic(err)
    }
    block, err := aes.NewCipher(bKey)
    if err != nil {
        panic(err)
    }
    mode := cipher.NewCBCDecrypter(block, bIV)
    mode.CryptBlocks([]byte(cipherTextDecoded), []byte(cipherTextDecoded))
    return string(PKCS5UnPadding(cipherTextDecoded))
}