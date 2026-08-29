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

	"github.com/barktrace/bark/internal/alerts"
	"github.com/barktrace/bark/internal/auth"
	"github.com/barktrace/bark/internal/blobstore"
	"github.com/barktrace/bark/internal/config"
	"github.com/barktrace/bark/internal/coordination"
	"github.com/barktrace/bark/internal/cronmon"
	"github.com/barktrace/bark/internal/httpapi"
	"github.com/barktrace/bark/internal/maintenance"
	"github.com/barktrace/bark/internal/store"
	"github.com/barktrace/bark/internal/uptime"
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
	var blobs blobstore.Backend
	if cfg.BlobBackend == "s3" {
		blobs, err = blobstore.NewS3(blobstore.S3Config{
			Endpoint: cfg.S3.Endpoint, Region: cfg.S3.Region, Bucket: cfg.S3.Bucket,
			AccessKey: cfg.S3.AccessKey, SecretKey: cfg.S3.SecretKey, SessionToken: cfg.S3.SessionToken,
			Prefix: cfg.S3.Prefix, TempDir: cfg.DataDir, AllowHTTP: cfg.S3.AllowHTTP,
		})
		if err != nil {
			return fmt.Errorf("configure S3 blob storage: %w", err)
		}
	}
	st, err := store.OpenWithDatabase(ctx, cfg.DataDir, blobs, cfg.DatabaseURL, cfg.DatabaseAuthToken)
	if err != nil {
		return err
	}
	defer st.Close()
	authentication, err := auth.New(ctx, cfg, st)
	if err != nil {
		return err
	}
	uptimeService := uptime.New(st, cfg.UptimeAllowPrivateTargets)
	coordinator := coordination.New(st.DB)
	maintenanceService := maintenance.New(st)
	alertService := alerts.New(st, cfg.SMTP)
	cronService := cronmon.New(st)
	go coordinator.Run(ctx, "uptime", 0, 5*time.Second, uptimeService.RunDue)
	go coordinator.Run(ctx, "retention", time.Minute, 6*time.Hour, maintenanceService.CleanupAll)
	go coordinator.Run(ctx, "alerts", 0, 10*time.Second, alertService.DeliverPending)
	go coordinator.Run(ctx, "cron", time.Minute, time.Minute, func(ctx context.Context) { cronService.MarkMissed(ctx, time.Now().UTC()) })
	api := httpapi.New(cfg, st, authentication, uptimeService)
	go api.RunIngestion(ctx)
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
	database := cfg.DataDir
	if cfg.DatabaseURL != "" {
		database = "remote libSQL"
	}
	slog.Info("barktrace listening", "address", cfg.Addr, "ui", "/ui/", "database", database)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
