// Package alert - webhook.go implements the generic HTTP webhook sink.
// The payload is the canonical wireEvent JSON; transport failures and 5xx
// responses are retried exactly once before being reported to the router.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// defaultHTTPTimeout matches the documented sink default when
// SinkConfig.TimeoutSec is unset.
const defaultHTTPTimeout = 5 * time.Second

// WebhookSink POSTs each alert as JSON to a fixed URL.
type WebhookSink struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// NewWebhook validates the sink config and builds the HTTP client. A missing
// URL is an error; a missing timeout falls back to 5 seconds.
func NewWebhook(cfg config.SinkConfig, log *slog.Logger) (*WebhookSink, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("alert: webhook sink requires url")
	}
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &WebhookSink{
		url:    cfg.URL,
		client: &http.Client{Timeout: timeout},
		log:    log,
	}, nil
}

// Name implements Sink.
func (w *WebhookSink) Name() string { return "webhook" }

// Send delivers one event. One retry is attempted on transport errors and
// HTTP 5xx; 4xx responses are permanent and returned immediately.
func (w *WebhookSink) Send(ctx context.Context, ev *events.Event) error {
	payload := renderEvent(ev)
	status, err := postJSON(ctx, w.client, w.url, payload)
	if err == nil && status >= 200 && status < 300 {
		return nil
	}
	if err != nil || status >= 500 {
		// Retryable: network error or server-side failure. The retry reuses
		// ctx, so an already-canceled/deadlined context fails fast.
		status, err = postJSON(ctx, w.client, w.url, payload)
		if err != nil {
			return fmt.Errorf("alert: webhook %s: %w", w.url, err)
		}
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("alert: webhook %s returned status %d", w.url, status)
	}
	return nil
}

// postJSON marshals v and POSTs it with the dbguard User-Agent. It returns
// the HTTP status code together with any transport error (err non-nil means
// the request never completed and is considered retryable).
func postJSON(ctx context.Context, client *http.Client, url string, v any) (int, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return 0, fmt.Errorf("alert: marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("alert: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "dbguard/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	return resp.StatusCode, nil
}
