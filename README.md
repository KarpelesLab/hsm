# HSM Library

A Go library providing a unified interface for Hardware Security Module (HSM) operations, with support for both hardware (YubiHSM2) and software-based implementations.

## Features

- Unified `HSM` interface for multiple backends
- YubiHSM2 support via HTTP connector (SCP03 secure channel)
- Software HSM for development and testing (BoltDB-backed)
- Key operations: listing, signing (ECDSA, EdDSA, RSA)
- Certificate storage and retrieval
- Automatic session management with keep-alive

## Installation

```bash
go get github.com/KarpelesLab/hsm
```

## Quick Start

```go
package main

import (
    "log"
    "os"

    "github.com/KarpelesLab/hsm"
)

func main() {
    // Set the HSM type via environment variable
    os.Setenv("HSM", "software")

    // Create HSM instance
    h, err := hsm.New()
    if err != nil {
        log.Fatal(err)
    }

    // List keys by name (auto-generates in software mode)
    keys, err := h.ListKeysByName("mykey")
    if err != nil {
        log.Fatal(err)
    }

    // Use the key for signing
    key := keys[0]
    log.Printf("Key: %s", key.String())
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HSM` | HSM backend type: `software` or `yubihsm2` | (required) |
| `YUBIHSM2_ADDR` | YubiHSM2 connector address | `localhost:12345` |

### Software HSM

The software HSM stores keys in an unencrypted BoltDB database. **This is intended for development and testing only.**

Storage location: `~/.config/hsm/hsmdata.db`

```bash
HSM=software ./myapp
```

### YubiHSM2

Requires the [YubiHSM2 connector](https://developers.yubico.com/YubiHSM2/Component_Reference/yubihsm-connector/) to be running.

```bash
# Start the connector
yubihsm-connector -d

# Run your application
HSM=yubihsm2 ./myapp

# Or with a custom connector address
HSM=yubihsm2 YUBIHSM2_ADDR=192.168.1.100:12345 ./myapp
```

## API Reference

### HSM Interface

```go
type HSM interface {
    Ready() bool
    ListKeys() ([]Key, error)
    ListKeysByName(name string) ([]Key, error)
    PutCertificate(name string, cert *x509.Certificate) error
    GetCertificate(name string) (*x509.Certificate, error)
}
```

### Key Interface

```go
type Key interface {
    crypto.Signer
    PublicBlob() ([]byte, error)
    String() string
}
```

### Supported Algorithms

#### YubiHSM2
- **ECDSA**: P-256, P-384, P-521
- **EdDSA**: Ed25519
- **RSA**: 2048, 3072, 4096 (PKCS#1 and PSS signing)

#### Software HSM
- **ECDSA**: P-256 (auto-generated keys)

## Examples

### Signing Data

```go
import (
    "crypto"
    "crypto/rand"
    "crypto/sha256"
)

// Get a key
keys, _ := h.ListKeysByName("signing-key")
key := keys[0]

// Hash and sign
message := []byte("data to sign")
hash := sha256.Sum256(message)
signature, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
```

### Certificate Storage

```go
import "crypto/x509"

// Store a certificate
err := h.PutCertificate("my-cert", cert)

// Retrieve a certificate
cert, err := h.GetCertificate("my-cert")
```

### Direct YubiHSM2 Usage

```go
import "github.com/KarpelesLab/hsm/yubihsm2"

// Create connector
connector := yubihsm2.NewHTTPConnector("localhost:12345")

// Check status
status, err := connector.GetStatus()
fmt.Printf("YubiHSM2 version: %s\n", status.Version)

// Create authenticated session
sm, err := yubihsm2.NewSessionManager(connector, 1, "password")

// Generate a key
keyID, err := sm.GenerateAsymmetricKey(
    0,                              // 0 = auto-assign ID
    []byte("my-key"),               // label
    yubihsm2.Domain1,               // domains
    yubihsm2.AsymmetricSignEcdsa,   // capabilities
    yubihsm2.Secp256r1,             // algorithm
)
```

## Testing

```bash
# Run all tests
go test ./...

# Run with verbose output
go test ./... -v

# Run with coverage
go test ./... -cover
```

## Security Considerations

- The software HSM stores keys **unencrypted** - use only for development
- YubiHSM2 communication uses SCP03 secure channels with AES-128 encryption
- Session keys are derived using PBKDF2 (10,000 iterations, SHA-256)
- Sessions automatically rotate after 10,000 messages
- Passwords are not stored in memory; only derived keys are retained

## License

See LICENSE file for details.
