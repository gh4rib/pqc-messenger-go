# Post-Quantum Privacy Guard (Golang Edition)

A Prototype Post-Quantum Cryptographic (PQC) Privacy Guard built in Go 1.25 using liboqs. 

This engine utilizes a **Hybrid KEM Architecture** (Classical Elliptic Curve + Lattice-based Cryptography) and a strict **Hash-and-Sign** paradigm to guarantee NIST Level 5 quantum resistance, seamless file transmission, and absolute memory safety across the CGO boundary.

## Features

- **Crypto-Agility:** Dynamically swap Key Encapsulation Mechanisms (KEMs), Digital Signatures, Hash functions, and Symmetric Ciphers based on recipient profiles.
- **Hybrid Key Exchange:** Combines classical `X25519` with Post-Quantum KEMs to ensure security against both traditional and quantum adversaries.
- **Strict Memory Sanitization:** Utilizes `oqs.MemCleanse()` to aggressively zero-out lattice secrets and master keys from RAM to prevent cold-boot and memory scraping attacks.
- **CGO Boundary Protection:** Implements deep-copy byte cloning (`cloneBytes`) and a fixed-length Hash-and-Sign digest pipeline to prevent Go garbage-collector pointer corruption and dangling C-memory wipes.
- **Air-Gapped PKI:** Generates offline public/private keyrings for secure, file-based identity routing.

## Supported Cryptographic Primitives

The engine interfaces natively with the C-based `liboqs` to support the latest FIPS 204/205 drafts and conservative pre-standardization algorithms:

| Category | Supported Algorithms |
| :--- | :--- |
| **Post-Quantum KEM** | `ML-KEM-768`, `ML-KEM-1024`, `NTRU-HPS-4096-1229`, `Kyber1024` |
| **Classical KEM** | `X25519` (ECDH) |
| **PQ Digital Signatures** | `ML-DSA-65`, `ML-DSA-87`, `SLH_DSA_PURE_SHA2_256S`, `Falcon-1024` |
| **Symmetric AEAD** | `AES-256-GCM`, `ChaCha20-Poly1305` |
| **Key Derivation (KDF)** | `SHA-384`, `SHA-512`, `SHAKE-256` (Sponge XOF) |

## Prerequisites

- **Go 1.25+** (Required for the latest `crypto` and `hash` interface optimizations).
- **liboqs:** The Open Quantum Safe C library must be compiled and installed on your system.
- **liboqs-go:** The Golang wrapper for `liboqs`.

Ensure your CGO environment variables are configured to point to your `liboqs` build:
```bash

sudo mkdir -p /usr/local/lib/pkgconfig

sudo tee /usr/local/lib/pkgconfig/liboqs-go.pc > /dev/null << 'EOF'
LIBOQS_INCLUDE_DIR=/usr/local/include
LIBOQS_LIB_DIR=/usr/local/lib

Name: liboqs-go
Description: liboqs CGO pkg-config file for Go bindings
Version: 0.15.0
Cflags: -I${LIBOQS_INCLUDE_DIR}
Libs: -L${LIBOQS_LIB_DIR} -loqs
EOF

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:$PKG_CONFIG_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
export CGO_CFLAGS="-I/usr/local/include -I/usr/include"
export CGO_LDFLAGS="-L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -loqs"

go get github.com/open-quantum-safe/liboqs-go/oqs
```

## Installation & Build

Clone the repository and build the interactive CLI binary:

```bash
cd pqc-messaging-go
go mod tidy
go build -o pqc-messenger main.go

```

### Usage Guide

Launch the interactive CLI:

```bash
./pqc-messenger

```

## Establish an Identity (PKI Setup)

Select **Option 1** to generate a new offline keypair. You will be prompted to choose a security profile (e.g., NIST Level 5 `ML-KEM-1024` + `ML-DSA-87`).

- This creates two folders: `./keys_name/private` (Keep Secret) and `./keys_name/public` (Share with friends).
- The `profile.json` inside dictates your preferred routing algorithms.

## Encrypt & Sign a File (Send)

Select **Option 2** to encrypt a payload for a recipient.

- **Inputs needed:** Path to your private folder, path to the recipient's public folder, and the file you wish to send (e.g., `secret.pdf`).
- **Output:** Generates an `outbox_msg.pqp` (Post-Quantum Packet) containing the serialized JSON envelope.

## Decrypt & Verify a File (Receive)

Select **Option 3** to verify the cryptographic signature and decrypt the payload.

- **Inputs needed:** Path to your private folder, path to the sender's public folder, and the `.pqp` packet.
- **Output:** Upon mathematical verification of the signature and AEAD MAC tag, the engine outputs the decrypted file with a precise timestamp (e.g., `decrypted_msg_20260531_150405.txt`).

## Security Architecture Notes

This framework addresses several notorious issues in Post-Quantum integration:

1. **Dangling Pointers:** The `liboqs` C library aggressively frees memory structures. My `cloneBytes` function ensures that extracted lattice keys are safely ported into Go's garbage-collected heap before the C thread terminates.
2. **Fiat-Shamir Sensitivity:** Algorithms like ML-DSA are highly sensitive to data serialization. My engine constructs a rigid byte-bundle combining the routing suite, ciphertext, nonce, and sender public key, strictly hashing it via `SHA-512` before passing it to the signature engine. This "Authenticated Negotiation" ensures an attacker cannot silently downgrade the cipher suite inside the JSON.
