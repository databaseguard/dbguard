// Package alert - slack.go implements the Slack Incoming-Webhook sink.
// Messages render as a one-line markdown headline plus one attachment whose
// color maps to severity and whose fields carry rule/user/db/client/SQL.
package alert

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// slackSQLSnippetMax caps the SQL shown per Slack field attachment.
const slackSQLSnippetMax = 200

// SlackSink posts alerts to a Slack incoming-webhook (or compatible relay,
// e.g. Mattermost, Matrix bridge).
type SlackSink struct {
	url    string
	client *http.Client
	log    *slog.Logger
}

// slackPayload is the Slack chat.postMessage "payload" shape used by
// incoming webhooks.
type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

// slackAttachment is one colored block of fields below the headline.
type slackAttachment struct {
	Color  string       `json:"color"`
	Fields []slackField `json:"fields"`
}

// slackField is a single title/value row ("short" = render two per row).
type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// NewSlack validates the sink config; a URL is mandatory.
func NewSlack(cfg config.SinkConfig, log *slog.Logger) (*SlackSink, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.URL == "" {
		return nil, fmt.Errorf("alert: slack sink requires url")
	}
	timeout := time.Duration(cfg.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &SlackSink{
		url:    cfg.URL,
		client: &http.Client{Timeout: timeout},
		log:    log,
	}, nil
}

// Name implements Sink.
func (s *SlackSink) Name() string { return "slack" }

// slackColor maps severity onto Slack attachment colors.
func slackColor(sev events.Severity) string {
	switch sev {
	case events.SevCritical, events.SevHigh:
		return "danger"
	case events.SevMedium:
		return "warning"
	default:
		return "good"
	}
}

// Send renders and posts one event. No retry: Slack webhooks are best-effort
// surfaces and the router already counts/logs failures.
func (s *SlackSink) Send(ctx context.Context, ev *events.Event) error {
	headline := ev.Message
	if headline == "" {
		headline = string(ev.Type)
	}
	text := fmt.Sprintf("[DBGUARD %s] %s", strings.ToUpper(string(ev.Severity)), headline)

	attach := slackAttachment{
		Color: slackColor(ev.Severity),
		Fields: []slackField{
			{Title: "Rule", Value: orDash(ev.RuleID), Short: true},
			{Title: "User", Value: orDash(ev.User), Short: true},
			{Title: "Database", Value: orDash(ev.Database), Short: true},
			{Title: "Client", Value: orDash(ev.ClientIP), Short: true},
			{Title: "SQL", Value: snippet(ev.SQL, slackSQLSnippetMax), Short: false},
		},
	}
	status, err := postJSON(ctx, s.client, s.url, slackPayload{
		Text:        text,
		Attachments: []slackAttachment{attach},
	})
	if err != nil {
		return fmt.Errorf("alert: slack %s: %w", s.url, err)
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("alert: slack %s returned status %d", s.url, status)
	}
	return nil
}

// orDash renders empty strings as "-" so Slack fields stay aligned.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
