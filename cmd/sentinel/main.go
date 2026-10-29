// Command sentinel runs the Sentinel authorization service.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bytesizedme/sentinel/internal/config"
	"github.com/bytesizedme/sentinel/internal/httpapi"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("sentinel: %v", err)
	}
}

// run holds the real logic so errors can be returned (and deferred calls
// still run) instead of calling log.Fatal deep inside.
func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: httpapi.NewRouter(),
		// Timeouts stop slow or malicious clients from holding connections
		// open forever (e.g. the "slowloris" attack).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// ctx is cancelled when the user presses Ctrl+C (or the OS asks us to stop).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Run the server in a goroutine so main can wait for the signal.
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", cfg.Addr)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		// The server failed on its own (e.g. port already in use).
		return err
	case <-ctx.Done():
		log.Println("shutting down...")
	}

	// Give in-flight requests up to 10s to finish before giving up.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	// After Shutdown, ListenAndServe returns ErrServerClosed, which is expected.
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Println("stopped cleanly")
	return nil
}
