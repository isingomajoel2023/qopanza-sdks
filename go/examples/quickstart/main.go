// Quickstart for the Go SDK: one-line encryption, signing, and a scan.
//
// Run with:
//
//	QOPANZA_API_KEY=qsk_... go run ./examples/quickstart
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/isingomajoel2023/qopanza-sdks/go/qopanza"
)

func main() {
	apiKey := os.Getenv("QOPANZA_API_KEY")
	if apiKey == "" {
		log.Fatal("set QOPANZA_API_KEY (sign up at POST /v1/accounts; the key is shown once)")
	}

	client := qopanza.New(os.Getenv("QOPANZA_BASE_URL"), apiKey)
	ctx := context.Background()

	// One-line encryption: the platform provisions and reuses a managed
	// key, so there is no key management to do at all.
	sealed, err := client.Encrypt(ctx, "", []byte("customer sensitive information"))
	if err != nil {
		log.Fatalf("encrypt: %v", err)
	}
	opened, err := client.Decrypt(ctx, sealed)
	if err != nil {
		log.Fatalf("decrypt: %v", err)
	}
	fmt.Printf("round trip: %q (managed key: %v)\n", opened, sealed.UsedManagedKey)

	// Signatures with an explicit key.
	sigKey, err := client.CreateKey(ctx, "signature", "orders")
	if err != nil {
		log.Fatalf("create key: %v", err)
	}
	signed, err := client.Sign(ctx, sigKey.ID, []byte("order-42-confirmed"))
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	valid, err := client.Verify(ctx, sigKey.ID, []byte("order-42-confirmed"), signed.Signature)
	if err != nil {
		log.Fatalf("verify: %v", err)
	}
	fmt.Printf("signature valid: %v (%s)\n", valid, sigKey.Algorithm)

	// Discover what cryptography a file uses.
	run, err := client.ScanCode(ctx, "payments.py", "cipher = RSA.generate(2048)\nh = hashlib.md5(x)")
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	fmt.Printf("scan: %d asset(s), %d quantum-vulnerable\n", run.AssetsFound, run.QuantumVulnerable)

	posture, err := client.SecurityPosture(ctx)
	if err != nil {
		log.Fatalf("posture: %v", err)
	}
	fmt.Printf("posture: %d/100 (%s risk)\n", posture.Score, posture.QuantumRisk)
	for _, action := range posture.RecommendedActions {
		fmt.Printf("  - %s\n", action)
	}
}
