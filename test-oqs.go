package main

import (
	"fmt"
	"strings"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

func main() {
	fmt.Println("==================================================")
	fmt.Println("      LIBOQS SUPPORTED ALGORITHMS PROBE           ")
	fmt.Println("==================================================")

	// Fetch all enabled Signature algorithms
	sigs := oqs.EnabledSigs()
	fmt.Printf("\n[+] Supported Signature Algorithms (%d total):\n", len(sigs))
	for _, sig := range sigs {
		// Highlight SLH-DSA / SPHINCS+ / ML-DSA to make them easy to spot
		if strings.Contains(strings.ToLower(sig), "slh") || 
		   strings.Contains(strings.ToLower(sig), "sphincs") || 
		   strings.Contains(strings.ToLower(sig), "ml-dsa") || 
		   strings.Contains(strings.ToLower(sig), "dilithium") {
			fmt.Printf("    ---> %s\n", sig)
		} else {
			fmt.Printf("    - %s\n", sig)
		}
	}

	// Fetch all enabled KEM algorithms
	kems := oqs.EnabledKEMs()
	fmt.Printf("\n[+] Supported KEM Algorithms (%d total):\n", len(kems))
	for _, kem := range kems {
		if strings.Contains(strings.ToLower(kem), "ntru") || 
		   strings.Contains(strings.ToLower(kem), "ml-kem") || 
		   strings.Contains(strings.ToLower(kem), "kyber") {
			fmt.Printf("    ---> %s\n", kem)
		} else {
			fmt.Printf("    - %s\n", kem)
		}
	}
	fmt.Println("\n==================================================")
}
