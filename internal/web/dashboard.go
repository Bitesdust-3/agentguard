// Package web renders the local, privacy-minimized AgentGuard dashboard.
package web

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
)

//go:embed templates/*.html static/dashboard.css
var assets embed.FS

type Handler struct {
	db        *sql.DB
	version   string
	templates map[string]*template.Template
}

type pageData struct {
	Title    string
	Active   string
	Version  string
	Overview overviewData
	Events   eventsData
	Tools    toolsData
	Request  requestDetail
	Tool     toolDetail
}

type overviewData struct {
	Metrics metrics
	Recent  []audit.Event
}

type metrics struct {
	TotalChats       int
	Pass             int
	Redact           int
	Block            int
	Approval         int
	Detections       int
	PromptInjection  int
	Secret           int
	PII              int
	ToolCalls        int
	PendingApprovals int
}

type eventFilters struct {
	EventType     string
	Decision      string
	DetectionType string
}

type eventsData struct {
	Items   []audit.Event
	Filters eventFilters
}

type toolRow struct {
	ID             string
	ToolName       string
	Decision       string
	State          string
	ApprovalID     string
	ApprovalStatus string
	External       bool
	Destructive    bool
	Sensitive      bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type toolsData struct{ Items []toolRow }

type requestDetail struct {
	Found      bool
	ID         string
	Model      string
	Status     string
	Decision   string
	CreatedAt  time.Time
	DoneAt     *time.Time
	Detections []detectionRow
	Decisions  []decisionRow
	Events     []audit.Event
}

type toolDetail struct {
	Found       bool
	Call        toolRow
	Summary     string
	Result      string
	Approval    approvalRow
	HasApproval bool
	Decisions   []decisionRow
	Events      []audit.Event
}

type detectionRow struct {
	Type       string
	RuleID     string
	Score      float64
	Confidence float64
	Evidence   string
	Source     string
	CreatedAt  time.Time
}

type decisionRow struct {
	Stage     string
	Decision  string
	PolicyID  string
	RiskScore float64
	Reason    string
	CreatedAt time.Time
}

type approvalRow struct {
	ID          string
	Status      string
	RequestedAt time.Time
	DecidedAt   *time.Time
}

// New constructs a read-only dashboard over the existing SQLite tables.
func New(db *sql.DB, version string) (*Handler, error) {
	if db == nil {
		return nil, fmt.Errorf("dashboard database must not be nil")
	}
	functions := template.FuncMap{
		"formatTime":     formatTime,
		"formatTimePtr":  formatTimePtr,
		"formatScore":    formatScore,
		"decisionClass":  decisionClass,
		"detectionClass": detectionClass,
	}
	templates := make(map[string]*template.Template, 5)
	for _, name := range []string{"overview", "events", "tools", "request", "tool"} {
		tmpl, err := template.New("base.html").Funcs(functions).ParseFS(assets, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse dashboard %s template: %w", name, err)
		}
		templates[name] = tmpl
	}
	return &Handler{db: db, version: version, templates: templates}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && (r.URL.Path == "/dashboard" || r.URL.Path == "/dashboard/"):
		h.overview(w, r, false)
	case r.Method == http.MethodGet && r.URL.Path == "/dashboard/partials/overview":
		h.overview(w, r, true)
	case r.Method == http.MethodGet && r.URL.Path == "/dashboard/events":
		h.events(w, r, false)
	case r.Method == http.MethodGet && r.URL.Path == "/dashboard/partials/events":
		h.events(w, r, true)
	case r.Method == http.MethodGet && r.URL.Path == "/dashboard/tools":
		h.tools(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dashboard/requests/"):
		h.requestDetail(w, r, strings.TrimPrefix(r.URL.Path, "/dashboard/requests/"))
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/dashboard/tools/"):
		h.toolDetail(w, r, strings.TrimPrefix(r.URL.Path, "/dashboard/tools/"))
	case r.Method == http.MethodGet && r.URL.Path == "/dashboard/static/dashboard.css":
		h.static(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) overview(w http.ResponseWriter, r *http.Request, partial bool) {
	data, err := h.loadOverview(r.Context())
	if err != nil {
		http.Error(w, "dashboard query failed", http.StatusInternalServerError)
		return
	}
	if partial {
		h.render(w, "overview", "overview_content", pageData{Overview: data})
		return
	}
	h.render(w, "overview", "base", pageData{Title: "Overview", Active: "overview", Version: h.version, Overview: data})
}

func (h *Handler) events(w http.ResponseWriter, r *http.Request, partial bool) {
	filters := eventFilters{EventType: r.URL.Query().Get("event_type"), Decision: r.URL.Query().Get("decision"), DetectionType: r.URL.Query().Get("detection_type")}
	items, err := audit.New(h.db).List(r.Context(), audit.Filter{EventType: filters.EventType, Decision: filters.Decision, DetectionType: filters.DetectionType, Limit: 100})
	if err != nil {
		http.Error(w, "dashboard query failed", http.StatusInternalServerError)
		return
	}
	data := eventsData{Items: items, Filters: filters}
	if partial {
		h.render(w, "events", "events_table", pageData{Events: data})
		return
	}
	h.render(w, "events", "base", pageData{Title: "Security Events", Active: "events", Version: h.version, Events: data})
}

func (h *Handler) tools(w http.ResponseWriter, r *http.Request) {
	items, err := h.listTools(r.Context())
	if err != nil {
		http.Error(w, "dashboard query failed", http.StatusInternalServerError)
		return
	}
	h.render(w, "tools", "base", pageData{Title: "Tools & Approval", Active: "tools", Version: h.version, Tools: toolsData{Items: items}})
}

func (h *Handler) requestDetail(w http.ResponseWriter, r *http.Request, id string) {
	detail, err := h.loadRequestDetail(r.Context(), id)
	if err != nil {
		http.Error(w, "dashboard query failed", http.StatusInternalServerError)
		return
	}
	if !detail.Found {
		http.NotFound(w, r)
		return
	}
	h.render(w, "request", "base", pageData{Title: "Request Detail", Active: "events", Version: h.version, Request: detail})
}

func (h *Handler) toolDetail(w http.ResponseWriter, r *http.Request, id string) {
	detail, err := h.loadToolDetail(r.Context(), id)
	if err != nil {
		http.Error(w, "dashboard query failed", http.StatusInternalServerError)
		return
	}
	if !detail.Found {
		http.NotFound(w, r)
		return
	}
	h.render(w, "tool", "base", pageData{Title: "Tool Detail", Active: "tools", Version: h.version, Tool: detail})
}

func (h *Handler) static(w http.ResponseWriter, _ *http.Request) {
	content, err := fs.ReadFile(assets, "static/dashboard.css")
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(content)
}

func (h *Handler) render(w http.ResponseWriter, page, name string, data pageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates[page].ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "dashboard render failed", http.StatusInternalServerError)
	}
}

func (h *Handler) loadOverview(ctx context.Context) (overviewData, error) {
	var data overviewData
	counts := []struct {
		destination *int
		query       string
	}{
		{&data.Metrics.TotalChats, "SELECT COUNT(*) FROM requests"},
		{&data.Metrics.Pass, "SELECT COUNT(*) FROM requests WHERE final_decision = 'PASS'"},
		{&data.Metrics.Redact, "SELECT COUNT(*) FROM requests WHERE final_decision = 'REDACT'"},
		{&data.Metrics.Block, "SELECT COUNT(*) FROM requests WHERE final_decision = 'BLOCK'"},
		{&data.Metrics.Approval, "SELECT COUNT(*) FROM tool_calls WHERE decision = 'APPROVAL'"},
		{&data.Metrics.Detections, "SELECT COUNT(*) FROM detections"},
		{&data.Metrics.PromptInjection, "SELECT COUNT(*) FROM detections WHERE detection_type = 'PROMPT_INJECTION'"},
		{&data.Metrics.Secret, "SELECT COUNT(*) FROM detections WHERE detection_type = 'SECRET'"},
		{&data.Metrics.PII, "SELECT COUNT(*) FROM detections WHERE detection_type = 'PII'"},
		{&data.Metrics.ToolCalls, "SELECT COUNT(*) FROM tool_calls"},
		{&data.Metrics.PendingApprovals, "SELECT COUNT(*) FROM approvals WHERE status = 'PENDING'"},
	}
	for _, count := range counts {
		if err := h.db.QueryRowContext(ctx, count.query).Scan(count.destination); err != nil {
			return overviewData{}, err
		}
	}
	items, err := audit.New(h.db).List(ctx, audit.Filter{Limit: 8})
	if err != nil {
		return overviewData{}, err
	}
	data.Recent = items
	return data, nil
}

func (h *Handler) listTools(ctx context.Context) ([]toolRow, error) {
	rows, err := h.db.QueryContext(ctx, `SELECT c.id,c.tool_name,c.decision,c.state,
		COALESCE(a.id,''),COALESCE(a.status,''),c.external,c.destructive,c.sensitive,c.created_at,c.updated_at
		FROM tool_calls c LEFT JOIN approvals a ON a.tool_call_id=c.id ORDER BY c.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]toolRow, 0)
	for rows.Next() {
		item, err := scanToolRow(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (h *Handler) loadRequestDetail(ctx context.Context, id string) (requestDetail, error) {
	var detail requestDetail
	var created string
	var completedValue sql.NullString
	err := h.db.QueryRowContext(ctx, `SELECT id,model,status,COALESCE(final_decision,''),created_at,completed_at FROM requests WHERE id=?`, id).Scan(&detail.ID, &detail.Model, &detail.Status, &detail.Decision, &created, &completedValue)
	if err == sql.ErrNoRows {
		return detail, nil
	}
	if err != nil {
		return detail, err
	}
	detail.Found = true
	detail.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if completedValue.Valid {
		parsed, err := time.Parse(time.RFC3339Nano, completedValue.String)
		if err == nil {
			detail.DoneAt = &parsed
		}
	}
	var errList error
	detail.Detections, errList = h.listDetections(ctx, "request_id", id)
	if errList != nil {
		return detail, errList
	}
	detail.Decisions, errList = h.listDecisions(ctx, "request_id", id)
	if errList != nil {
		return detail, errList
	}
	detail.Events, errList = audit.New(h.db).List(ctx, audit.Filter{RequestID: id, Limit: 100})
	return detail, errList
}

func (h *Handler) loadToolDetail(ctx context.Context, id string) (toolDetail, error) {
	var detail toolDetail
	var created, updated string
	var approvalID, approvalStatus, requested sql.NullString
	var decided sql.NullString
	err := h.db.QueryRowContext(ctx, `SELECT c.id,c.tool_name,c.decision,c.state,COALESCE(a.id,''),COALESCE(a.status,''),
		c.external,c.destructive,c.sensitive,c.created_at,c.updated_at,c.arguments_summary,COALESCE(c.result_summary,''),
		a.requested_at,a.decided_at FROM tool_calls c LEFT JOIN approvals a ON a.tool_call_id=c.id WHERE c.id=?`, id).
		Scan(&detail.Call.ID, &detail.Call.ToolName, &detail.Call.Decision, &detail.Call.State, &approvalID, &approvalStatus,
			&detail.Call.External, &detail.Call.Destructive, &detail.Call.Sensitive, &created, &updated, &detail.Summary, &detail.Result, &requested, &decided)
	if err == sql.ErrNoRows {
		return detail, nil
	}
	if err != nil {
		return detail, err
	}
	detail.Found = true
	detail.Call.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	detail.Call.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	if approvalID.Valid && approvalID.String != "" {
		detail.HasApproval = true
		detail.Approval.ID, detail.Approval.Status = approvalID.String, approvalStatus.String
		detail.Approval.RequestedAt, _ = time.Parse(time.RFC3339Nano, requested.String)
		if decided.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, decided.String)
			if err == nil {
				detail.Approval.DecidedAt = &parsed
			}
		}
	}
	var errList error
	detail.Decisions, errList = h.listDecisions(ctx, "tool_call_id", id)
	if errList != nil {
		return detail, errList
	}
	detail.Events, errList = audit.New(h.db).List(ctx, audit.Filter{ToolCallID: id, Limit: 100})
	return detail, errList
}

func (h *Handler) listDetections(ctx context.Context, column, id string) ([]detectionRow, error) {
	query := `SELECT detection_type,rule_id,score,confidence,evidence,source,created_at FROM detections WHERE ` + column + `=? ORDER BY created_at DESC`
	rows, err := h.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]detectionRow, 0)
	for rows.Next() {
		var item detectionRow
		var created string
		if err := rows.Scan(&item.Type, &item.RuleID, &item.Score, &item.Confidence, &item.Evidence, &item.Source, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		items = append(items, item)
	}
	return items, rows.Err()
}

func (h *Handler) listDecisions(ctx context.Context, column, id string) ([]decisionRow, error) {
	query := `SELECT stage,decision,policy_id,risk_score,reason,created_at FROM policy_decisions WHERE ` + column + `=? ORDER BY created_at DESC`
	rows, err := h.db.QueryContext(ctx, query, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]decisionRow, 0)
	for rows.Next() {
		var item decisionRow
		var created string
		if err := rows.Scan(&item.Stage, &item.Decision, &item.PolicyID, &item.RiskScore, &item.Reason, &created); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		items = append(items, item)
	}
	return items, rows.Err()
}

type rowScanner interface{ Scan(...any) error }

func scanToolRow(scanner rowScanner) (toolRow, error) {
	var item toolRow
	var created, updated string
	err := scanner.Scan(&item.ID, &item.ToolName, &item.Decision, &item.State, &item.ApprovalID, &item.ApprovalStatus, &item.External, &item.Destructive, &item.Sensitive, &created, &updated)
	if err != nil {
		return item, err
	}
	item.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	item.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updated)
	return item, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.UTC().Format("2006-01-02 15:04:05 UTC")
}

func formatTimePtr(value *time.Time) string {
	if value == nil {
		return "—"
	}
	return formatTime(*value)
}

func formatScore(value any) string {
	switch score := value.(type) {
	case float64:
		return fmt.Sprintf("%.2f", score)
	case *float64:
		if score != nil {
			return fmt.Sprintf("%.2f", *score)
		}
	}
	return "—"
}

func decisionClass(value string) string {
	switch value {
	case "PASS":
		return "pass"
	case "REDACT":
		return "redact"
	case "BLOCK":
		return "block"
	case "APPROVAL":
		return "approval"
	}
	return "neutral"
}

func detectionClass(value string) string {
	switch value {
	case "PII":
		return "pii"
	case "SECRET":
		return "secret"
	case "PROMPT_INJECTION":
		return "injection"
	}
	return "neutral"
}

var _ http.Handler = (*Handler)(nil)
