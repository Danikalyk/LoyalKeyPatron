package main

import (
	"LoyalKeyPatron/cryptography"
	"fmt"
)

func main() {
	loyalKey := cryptography.Crypto("Onliners", "Nevelin")

	fmt.Println(loyalKey)
}
