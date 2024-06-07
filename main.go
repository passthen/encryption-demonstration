package main

import (
	"fmt"
	"os"
	"regexp"

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
	fmt.Print("Please enter your custom iterations.(recommand more than 50)\n > ")
	fmt.Scanf("%d", &iterations)

	masterKey = KDF(userName, masterPassword, iterations, 32)

	fmt.Println("Here is your master key:")
	fmt.Println(masterKey)

	authenticationKey :=  KDFToServer(userName, masterKey)
	fmt.Println("Your key that store in server to authentication:\n" + string(authenticationKey))



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
	memory := uint32(128 * 1024)
	threads := uint8(4)
	keyLength := uint32(length)

	key := argon2.IDKey([]byte(payload), []byte(slat), time, memory, threads, keyLength)
	return key
}

func KDFToServer(masterPassword string, masterKey []byte) []byte {
	encryptPayload := KDF(masterPassword, string(masterKey), 1, 72)

    hashedPassword, err := bcrypt.GenerateFromPassword(encryptPayload, 20)
    if err != nil {
        fmt.Println(err)
        return []byte("")
    }
    return hashedPassword
}