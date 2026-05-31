package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"
	"time"

	"github.com/open-quantum-safe/liboqs-go/oqs"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"
)

// =====================================================================
// 1. DOMAIN MODELS & WIRE STRUCTURES
// =====================================================================

type IdentityProfile struct {
	Name          string `json:"name"`
	KemVariant    string `json:"kem_variant"`
	SigVariant    string `json:"sig_variant"`
	CipherVariant string `json:"cipher_variant"`
	HashVariant   string `json:"hash_variant"`
}

type SessionSuite struct {
	KemVariant    string `json:"kem_variant"`
	HashVariant   string `json:"hash_variant"`
	CipherVariant string `json:"cipher_variant"`
	SigVariant    string `json:"sig_variant"`
}

type SecurePacket struct {
	Suite        SessionSuite `json:"suite"`
	SenderX25519 []byte       `json:"sender_x25519"`
	PQEncap      []byte       `json:"pq_encap"`
	Ciphertext   []byte       `json:"ciphertext"`
	Nonce        []byte       `json:"nonce"`
	Signature    []byte       `json:"signature"`
}

type Keyring struct {
	X25519Priv *ecdh.PrivateKey
	X25519Pub  *ecdh.PublicKey
	KEMPriv    []byte
	KEMPub     []byte
	SigPriv    []byte
	SigPub     []byte
}

// =====================================================================
// 2. MEMORY SAFETY & CRYPTO FACTORIES
// =====================================================================

// cloneBytes prevents CGO dangling pointer corruption by explicitly 
// copying C memory into Go's garbage-collected heap.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func deriveKey(hashName string, classicSecret, pqSecret []byte) []byte {
	if hashName == "SHAKE-256" {
		shake := sha3.NewShake256()
		shake.Write(classicSecret)
		shake.Write(pqSecret)
		out := make([]byte, 64)
		shake.Read(out)
		return out
	}

	var h hash.Hash
	switch hashName {
	case "SHA-256":
		h = sha256.New()
	case "SHA-384":
		h = sha512.New384()
	case "SHA-512":
		fallthrough
	default:
		h = sha512.New()
	}

	h.Write(classicSecret)
	h.Write(pqSecret)
	return h.Sum(nil)
}

func getAEAD(cipherName string, key []byte) (cipher.AEAD, error) {
	symmetricKey := make([]byte, 32)
	copy(symmetricKey, key[:32])

	switch cipherName {
	case "AES-256-GCM":
		block, err := aes.NewCipher(symmetricKey)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AES block: %w", err)
		}
		return cipher.NewGCM(block)

	case "CHACHA20-POLY1305":
		return chacha20poly1305.New(symmetricKey)

	default:
		return nil, fmt.Errorf("unsupported cipher: %s", cipherName)
	}
}

// buildBundle creates an immutable byte-stream for the signature without relying on non-deterministic JSON.
func buildBundle(suite SessionSuite, ciphertext, nonce, senderPub []byte) []byte {
	length := len(suite.KemVariant) + len(suite.HashVariant) + len(suite.CipherVariant) + len(suite.SigVariant) + len(ciphertext) + len(nonce) + len(senderPub)
	bundle := make([]byte, 0, length)
	
	bundle = append(bundle, []byte(suite.KemVariant)...)
	bundle = append(bundle, []byte(suite.HashVariant)...)
	bundle = append(bundle, []byte(suite.CipherVariant)...)
	bundle = append(bundle, []byte(suite.SigVariant)...)
	bundle = append(bundle, ciphertext...)
	bundle = append(bundle, nonce...)
	bundle = append(bundle, senderPub...)
	
	return bundle
}

// =====================================================================
// 3. CORE PROTOCOL ENGINE
// =====================================================================

func EncryptAndSign(message []byte, senderProfile IdentityProfile, sender Keyring, recipientProfile IdentityProfile, recipientPub Keyring) (SecurePacket, error) {
	// The session adopts the Recipient's routing preferences, but the Sender's signature identity
	session := SessionSuite{
		KemVariant:    recipientProfile.KemVariant,
		HashVariant:   recipientProfile.HashVariant,
		CipherVariant: recipientProfile.CipherVariant,
		SigVariant:    senderProfile.SigVariant,
	}

	classicSecret, err := sender.X25519Priv.ECDH(recipientPub.X25519Pub)
	if err != nil {
		return SecurePacket{}, fmt.Errorf("classical ecdh failed: %w", err)
	}

	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()
	if err := kem.Init(session.KemVariant, nil); err != nil {
		return SecurePacket{}, fmt.Errorf("kem init failed for %s: %w", session.KemVariant, err)
	}
	pqCiphertext, pqSecret, err := kem.EncapSecret(recipientPub.KEMPub)
	if err != nil {
		return SecurePacket{}, fmt.Errorf("kem encapsulation failed: %w", err)
	}
	defer oqs.MemCleanse(pqSecret)

	masterSecret := deriveKey(session.HashVariant, classicSecret, pqSecret)
	defer oqs.MemCleanse(masterSecret)

	aead, err := getAEAD(session.CipherVariant, masterSecret)
	if err != nil {
		return SecurePacket{}, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SecurePacket{}, fmt.Errorf("rng failure reading nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, message, nil)

	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init(session.SigVariant, sender.SigPriv); err != nil {
		return SecurePacket{}, fmt.Errorf("signature init failed for %s: %w", session.SigVariant, err)
	}

	bundle := buildBundle(session, ciphertext, nonce, sender.X25519Pub.Bytes())
	
	// Hash-and-Sign Paradigm to protect the CGO boundary
	digest := sha512.Sum512(bundle)
	digestSlice := cloneBytes(digest[:])
	
	signature, err := signer.Sign(digestSlice)
	if err != nil {
		return SecurePacket{}, fmt.Errorf("bundle signing failed: %w", err)
	}

	return SecurePacket{
		Suite:        session,
		SenderX25519: sender.X25519Pub.Bytes(),
		PQEncap:      cloneBytes(pqCiphertext),
		Ciphertext:   ciphertext,
		Nonce:        nonce,
		Signature:    cloneBytes(signature),
	}, nil
}

func VerifyAndDecrypt(packet SecurePacket, recipient Keyring, senderPub Keyring) ([]byte, error) {
	session := packet.Suite

	signer := oqs.Signature{}
	defer signer.Clean()
	if err := signer.Init(session.SigVariant, nil); err != nil {
		return nil, fmt.Errorf("signature engine initialization failed: %w", err)
	}

	bundle := buildBundle(session, packet.Ciphertext, packet.Nonce, packet.SenderX25519)
	
	// Reconstruct exact 64-byte digest array
	digest := sha512.Sum512(bundle)
	digestSlice := cloneBytes(digest[:])
	
	isValid, err := signer.Verify(digestSlice, packet.Signature, senderPub.SigPub)
	if err != nil {
		return nil, fmt.Errorf("liboqs math error during signature verification: %w", err)
	}
	if !isValid {
		return nil, fmt.Errorf("CRITICAL: signature is invalid (packet altered in transit)")
	}

	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()
	if err := kem.Init(session.KemVariant, recipient.KEMPriv); err != nil {
		return nil, fmt.Errorf("kem engine initialization failed: %w", err)
	}

	pqSecret, err := kem.DecapSecret(packet.PQEncap)
	if err != nil {
		return nil, fmt.Errorf("pq decapsulation logic failure: %w", err)
	}
	defer oqs.MemCleanse(pqSecret)

	ephemeralSenderPub, err := ecdh.X25519().NewPublicKey(packet.SenderX25519)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 key serialized within frame: %w", err)
	}
	classicSecret, err := recipient.X25519Priv.ECDH(ephemeralSenderPub)
	if err != nil {
		return nil, fmt.Errorf("classical ecdh failure: %w", err)
	}

	masterSecret := deriveKey(session.HashVariant, classicSecret, pqSecret)
	defer oqs.MemCleanse(masterSecret)

	aead, err := getAEAD(session.CipherVariant, masterSecret)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, packet.Nonce, packet.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("CRITICAL: mac tag validation failure; ciphertext corrupt")
	}

	return plaintext, nil
}

// =====================================================================
// 4. FILE SYSTEM I/O & PKI MANAGEMENT
// =====================================================================

func GenerateAndSaveIdentity(name string, profile IdentityProfile) {
	fmt.Println("\n[*] Generating keys. This may take a moment for large parameter sets...")
	
	x25519Priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	
	kem := oqs.KeyEncapsulation{}
	defer kem.Clean()
	kem.Init(profile.KemVariant, nil)
	kemPub, _ := kem.GenerateKeyPair()
	kemPriv := kem.ExportSecretKey()

	signer := oqs.Signature{}
	defer signer.Clean()
	signer.Init(profile.SigVariant, nil)
	sigPub, _ := signer.GenerateKeyPair()
	sigPriv := signer.ExportSecretKey()

	privDir := fmt.Sprintf("./keys_%s/private", name)
	pubDir := fmt.Sprintf("./keys_%s/public", name)
	os.MkdirAll(privDir, 0700)
	os.MkdirAll(pubDir, 0755)

	profBytes, _ := json.MarshalIndent(profile, "", "  ")
	os.WriteFile(pubDir+"/profile.json", profBytes, 0644)
	os.WriteFile(privDir+"/profile.json", profBytes, 0600)

	os.WriteFile(privDir+"/x25519.priv", x25519Priv.Bytes(), 0600)
	os.WriteFile(pubDir+"/x25519.pub", x25519Priv.PublicKey().Bytes(), 0644)
	os.WriteFile(privDir+"/kem.priv", cloneBytes(kemPriv), 0600)
	os.WriteFile(pubDir+"/kem.pub", cloneBytes(kemPub), 0644)
	os.WriteFile(privDir+"/sig.priv", cloneBytes(sigPriv), 0600)
	os.WriteFile(pubDir+"/sig.pub", cloneBytes(sigPub), 0644)

	fmt.Printf("[+] Identity '%s' established successfully.\n", name)
	fmt.Printf("    -> Private keys saved to: %s (KEEP SECRET)\n", privDir)
	fmt.Printf("    -> Public keys saved to:  %s (SHARE THIS)\n", pubDir)
}

func LoadPrivateKeyring(privDir string) (IdentityProfile, Keyring, error) {
	profBytes, err := os.ReadFile(privDir + "/profile.json")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read private profile.json: %w", err)
	}
	var prof IdentityProfile
	json.Unmarshal(profBytes, &prof)

	xPrivBytes, err := os.ReadFile(privDir + "/x25519.priv")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read x25519.priv: %w", err)
	}
	x25519Priv, err := ecdh.X25519().NewPrivateKey(xPrivBytes)
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("invalid x25519 private key: %w", err)
	}
	
	kemPriv, err := os.ReadFile(privDir + "/kem.priv")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read kem.priv: %w", err)
	}
	
	sigPriv, err := os.ReadFile(privDir + "/sig.priv")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read sig.priv: %w", err)
	}

	return prof, Keyring{
		X25519Priv: x25519Priv,
		X25519Pub:  x25519Priv.PublicKey(),
		KEMPriv:    kemPriv,
		SigPriv:    sigPriv,
	}, nil
}

func LoadPublicKeyring(pubDir string) (IdentityProfile, Keyring, error) {
	profBytes, err := os.ReadFile(pubDir + "/profile.json")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read public profile.json: %w", err)
	}
	var prof IdentityProfile
	json.Unmarshal(profBytes, &prof)

	xPubBytes, err := os.ReadFile(pubDir + "/x25519.pub")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read x25519.pub: %w", err)
	}
	x25519Pub, err := ecdh.X25519().NewPublicKey(xPubBytes)
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("invalid x25519 public key: %w", err)
	}
	
	kemPub, err := os.ReadFile(pubDir + "/kem.pub")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read kem.pub: %w", err)
	}
	
	sigPub, err := os.ReadFile(pubDir + "/sig.pub")
	if err != nil {
		return IdentityProfile{}, Keyring{}, fmt.Errorf("could not read sig.pub: %w", err)
	}

	return prof, Keyring{
		X25519Pub: x25519Pub,
		KEMPub:    kemPub,
		SigPub:    sigPub,
	}, nil
}

// =====================================================================
// 5. INTERACTIVE CLI MENU
// =====================================================================

func main() {
	reader := bufio.NewReader(os.Stdin)

	for {
		fmt.Println("\n=====================================================================")
		fmt.Println("             PQC-MESSENGER: CLI CRYPTO AGILITY ENGINE                ")
		fmt.Println("=====================================================================")
		fmt.Println(" 1) Generate New Identity (PKI Setup)")
		fmt.Println(" 2) Encrypt & Sign a File (Send)")
		fmt.Println(" 3) Decrypt & Verify a File (Receive)")
		fmt.Println(" 4) Exit")
		fmt.Println("=====================================================================")
		fmt.Print("Select an option [1-4]: ")

		option, _ := reader.ReadString('\n')
		option = strings.TrimSpace(option)

		switch option {
		case "1":
			fmt.Print("\nEnter a name for this identity (e.g., 'alice'): ")
			name, _ := reader.ReadString('\n')
			name = strings.TrimSpace(name)

			if name == "" {
				fmt.Println("[-] Name cannot be empty. Aborting.")
				continue
			}

			fmt.Println("\nSelect a Security Profile:")
			fmt.Println(" 1) NIST Level 3 (ML-KEM-768 + ML-DSA-65 + AES-256)")
			fmt.Println(" 2) NIST Level 5 (ML-KEM-1024 + ML-DSA-87 + AES-256)")
			fmt.Println(" 3) Level 5 Conservative (NTRU-1229 + SLH-DSA-256S + ChaCha20)")
			fmt.Print("Choice [1-3]: ")
			
			profChoice, _ := reader.ReadString('\n')
			profChoice = strings.TrimSpace(profChoice)

			var profile IdentityProfile
			profile.Name = name

			switch profChoice {
			case "1":
				profile.KemVariant = "ML-KEM-768"
				profile.SigVariant = "ML-DSA-65"
				profile.CipherVariant = "AES-256-GCM"
				profile.HashVariant = "SHA-384"
			case "2":
				profile.KemVariant = "ML-KEM-1024"
				profile.SigVariant = "ML-DSA-87"
				profile.CipherVariant = "AES-256-GCM"
				profile.HashVariant = "SHA-512"
			case "3":
				profile.KemVariant = "NTRU-HPS-4096-1229"
				profile.SigVariant = "SLH_DSA_PURE_SHA2_256S"
				profile.CipherVariant = "CHACHA20-POLY1305"
				profile.HashVariant = "SHAKE-256"
			default:
				fmt.Println("[-] Invalid choice. Aborting.")
				continue
			}

			GenerateAndSaveIdentity(name, profile)

		case "2":
			fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_alice/private): ")
			privPath, _ := reader.ReadString('\n')
			
			fmt.Print("Enter path to RECIPIENT'S public folder (e.g., ./keys_bob/public): ")
			pubPath, _ := reader.ReadString('\n')

			fmt.Print("Enter path to the file you want to send (e.g., secret.txt): ")
			filePath, _ := reader.ReadString('\n')
			filePath = strings.TrimSpace(filePath)
			
			msgBytes, err := os.ReadFile(filePath)
			if err != nil {
				fmt.Printf("[-] Failed to read message file: %v\n", err)
				continue
			}
			
			senderProf, senderKr, err := LoadPrivateKeyring(strings.TrimSpace(privPath))
			if err != nil {
				fmt.Printf("[-] Failed to load private keys: %v\n", err)
				continue
			}

			// We need the recipient's profile to extract the KEM and Cipher algorithms
			recipientProf, recipientKr, err := LoadPublicKeyring(strings.TrimSpace(pubPath))
			if err != nil {
				fmt.Printf("[-] Failed to load recipient public keys: %v\n", err)
				continue
			}

			packet, err := EncryptAndSign(msgBytes, senderProf, senderKr, recipientProf, recipientKr)
			if err != nil {
				fmt.Printf("[-] Encryption failed: %v\n", err)
				continue
			}

			packetBytes, _ := json.MarshalIndent(packet, "", "  ")
			outboxName := "outbox_msg.pqp"
			err = os.WriteFile(outboxName, packetBytes, 0644)
			if err != nil {
				fmt.Printf("[-] Failed to save packet: %v\n", err)
				continue
			}

			fmt.Printf("\n[+] SUCCESS! File encrypted, signed, and saved to '%s'\n", outboxName)
			fmt.Printf("    Packet Size: %d bytes\n", len(packetBytes))

		case "3":
			fmt.Print("\nEnter path to YOUR private folder (e.g., ./keys_bob/private): ")
			privPath, _ := reader.ReadString('\n')
			
			fmt.Print("Enter path to SENDER'S public folder (e.g., ./keys_alice/public): ")
			pubPath, _ := reader.ReadString('\n')

			fmt.Print("Enter path to the packet file (e.g., outbox_msg.pqp): ")
			pqpPath, _ := reader.ReadString('\n')

			// We drop the recipient profile here because the routing configuration is embedded in the packet
			_, recipientKr, err := LoadPrivateKeyring(strings.TrimSpace(privPath))
			if err != nil {
				fmt.Printf("[-] Failed to load private keys: %v\n", err)
				continue
			}

			// We drop the sender profile here for the same reason
			_, senderKr, err := LoadPublicKeyring(strings.TrimSpace(pubPath))
			if err != nil {
				fmt.Printf("[-] Failed to load sender public keys: %v\n", err)
				continue
			}

			packetBytes, err := os.ReadFile(strings.TrimSpace(pqpPath))
			if err != nil {
				fmt.Printf("[-] Failed to read packet file: %v\n", err)
				continue
			}

			var packet SecurePacket
			if err := json.Unmarshal(packetBytes, &packet); err != nil {
				fmt.Printf("[-] Failed to parse packet JSON: %v\n", err)
				continue
			}

			fmt.Printf("\n[*] Parsing packet... Signature Algorithm: %s | KEM: %s\n", packet.Suite.SigVariant, packet.Suite.KemVariant)

			recovered, err := VerifyAndDecrypt(packet, recipientKr, senderKr)
			if err != nil {
				fmt.Printf("[-] Decryption failed: %v\n", err)
				continue
			}

			// Generate timestamped output file
			timestamp := time.Now().Format("20060102_150405")
			outFilename := fmt.Sprintf("decrypted_msg_%s.txt", timestamp)

			err = os.WriteFile(outFilename, recovered, 0644)
			if err != nil {
				fmt.Printf("[-] Failed to save decrypted file: %v\n", err)
				continue
			}

			fmt.Printf("[+] VERIFICATION SUCCESSFUL. Identity proven.\n")
			fmt.Printf("[+] Decrypted file saved to: %s\n", outFilename)

		case "4":
			fmt.Println("Exiting PQC-Messenger...")
			return
		default:
			fmt.Println("[-] Invalid option. Please select 1-4.")
		}
	}
}
