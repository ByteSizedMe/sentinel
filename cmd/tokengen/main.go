// Command tokengen prints a signed dev JWT for calling Sentinel locally.
// It reads JWT_SECRET, JWT_ISSUER and JWT_AUDIENCE from the environment (the
// same settings the server uses), so there is no secret in the source.
// For local testing only.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/bytesizedme/sentinel/internal/auth"
	"github.com/bytesizedme/sentinel/internal/config"
)

func main() {
	subject := flag.String("sub", "dev-service", "subject (the calling service's identity)")
	ttl := flag.Duration("ttl", time.Hour, "how long the token stays valid")
	flag.Parse()

	// Reuse the server's config loading so the checks (e.g. minimum secret
	// length) are identical. It also needs DATABASE_URL, which `make` provides.
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		log.Fatalf("tokengen: %v", err)
	}
	token, err := auth.Mint(cfg.JWTSecret, cfg.JWTIssuer, cfg.JWTAudience, *subject, *ttl)
	if err != nil {
		log.Fatalf("tokengen: %v", err)
	}
	fmt.Println(token) // only the token goes to stdout so it can be captured
}
