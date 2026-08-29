package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/GhaziBenDahmane/barktrace/internal/alerts"
	"github.com/GhaziBenDahmane/barktrace/internal/auth"
	"github.com/GhaziBenDahmane/barktrace/internal/config"
	"github.com/GhaziBenDahmane/barktrace/internal/httpapi"
	"github.com/GhaziBenDahmane/barktrace/internal/maintenance"
	"github.com/GhaziBenDahmane/barktrace/internal/store"
	"github.com/GhaziBenDahmane/barktrace/internal/uptime"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "healthcheck" {
		if err := checkHealth(envOr("BARKTRACE_HEALTHCHECK_URL", "http://127.0.0.1:8080/readyz")); err != nil {
			slog.Error("health check failed", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func checkHealth(endpoint string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(endpoint)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4<<10))
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("readiness endpoint returned %s", response.Status)
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	st, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	authentication, err := auth.New(ctx, cfg, st)
	if err != nil {
		return err
	}
	uptimeService := uptime.New(st, cfg.UptimeAllowPrivateTargets)
	go uptimeService.Run(ctx)
	go maintenance.New(st).Run(ctx)
	go alerts.New(st).Run(ctx)
	api := httpapi.New(cfg, st, authentication, uptimeService)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           api.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	slog.Info("barktrace listening", "address", cfg.Addr, "ui", "/ui/", "database", cfg.DataDir)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
