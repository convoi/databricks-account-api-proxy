package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"databricks-account-api-proxy/internal/audit"
	"databricks-account-api-proxy/internal/auth"
	"databricks-account-api-proxy/internal/config"
	"databricks-account-api-proxy/internal/policy"
	"databricks-account-api-proxy/internal/proxy"
	"databricks-account-api-proxy/internal/whitelist"
)

var version = "0.1.0"

func main() {
	// Configure structured JSON logger for application events
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	logger := slog.New(jsonHandler)
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("Configuration validation failed", "error", err)
		os.Exit(1)
	}

	// Shared HTTP client with connection pooling
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Initialize components
	auditLogger := audit.NewLogger(os.Stdout)
	tokenMgr := auth.NewAdminTokenManager(cfg, httpClient)
	validator := auth.NewCallerValidator(cfg, httpClient)
	spnPolicy := policy.NewSPNManagerPolicy(cfg, tokenMgr, httpClient)
	nccPolicy := policy.NewNCCWorkspaceAdminPolicy(cfg, tokenMgr, httpClient)

	// Load calling SPN workspace whitelist if configured
	spnWhitelist, err := whitelist.LoadFromFile(cfg.ConfigFile)
	if err != nil {
		slog.Error("Failed to load SPN workspace whitelist config", "file", cfg.ConfigFile, "error", err)
		os.Exit(1)
	}
	if spnWhitelist.IsEnabled() {
		slog.Info("Loaded calling SPN workspace whitelist", "file", cfg.ConfigFile)
	}

	proxyServer := proxy.NewProxyServer(
		cfg,
		tokenMgr,
		validator,
		spnPolicy,
		nccPolicy,
		spnWhitelist,
		auditLogger,
		httpClient,
	)

	router := proxyServer.SetupRoutes()

	srv := &http.Server{
		Addr:         cfg.ProxyListenAddr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown handling
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		slog.Info("Starting Databricks Account API Scoped Proxy",
			"version", version,
			"listen_addr", cfg.ProxyListenAddr,
			"accounts_host", cfg.DatabricksAccountsHost,
		)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("Server listen error", "error", err)
			os.Exit(1)
		}
	}()

	<-stop
	slog.Info("Shutting down proxy gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("Server shutdown failed", "error", err)
		os.Exit(1)
	}

	slog.Info("Proxy stopped cleanly")
}
