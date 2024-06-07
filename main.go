package main

import (
	"golang.org/x/crypto/argon2"
	"fmt"
)

func main() {
	var userName string
	var masterPassword string
	var iterations int

	fmt.Print("Please enter your username.\n > ")
	fmt.Scanf("%s", &userName)
	fmt.Print("Please enter your master password.\n > ")
	fmt.Scanf("%s", &masterPassword)
	fmt.Print("Please enter your custom iterations.(recommand more than 50)\n > ")
	fmt.Scanf("%d", &iterations)

	masterKey := KDF(userName, masterPassword, iterations)
	fmt.Println("Here is your master key:\n", masterKey)



}

func KDF(userName, masterPassword string, iterations int) []byte {
	time := uint32(iterations)
    memory := uint32(128 * 1024)
    threads := uint8(10)
    keyLength := uint32(32)

    key := argon2.IDKey([]byte(masterPassword), []byte(userName), time, memory, threads, keyLength)
	return key
}

func KDFToServer(userName, masterPassword string, iterations int) []byte {
	time := uint32(iterations)
    memory := uint32(128 * 1024)
    threads := uint8(10)
    keyLength := uint32(32)

    key := argon2.IDKey([]byte(masterPassword), []byte(userName), time, memory, threads, keyLength)
	return key
}