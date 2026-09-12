package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bitesdust/agentguard/internal/audit"
	"github.com/bitesdust/agentguard/internal/benchmark"
	"github.com/bitesdust/agentguard/internal/config"
	"github.com/bitesdust/agentguard/internal/detection"
	"github.com/bitesdust/agentguard/internal/policy"
	"github.com/bitesdust/agentguard/internal/storage"
	"github.com/bitesdust/agentguard/internal/tools"
)

func TestDashboardOverviewEventsAndDetails(t *testing.T) {
	handler, _, requestID, toolID, approvalID, _ := testDashboard(t)
	overview, err := handler.loadOverview(context.Background())
	if err != nil {
		t.Fatalf("load overview: %v", err)
	}
	if overview.Metrics.TotalChats != 1 || overview.Metrics.Redact != 1 || overview.Metrics.Detections != 1 || overview.Metrics.PII != 1 || overview.Metrics.ToolCalls != 1 || overview.Metrics.PendingApprovals != 1 {
		t.Fatalf("unexpected overview metrics: %+v", overview.Metrics)
	}

	for _, test := range []struct {
		name string
		path string
		want []string
	}{
		{name: "overview", path: "/dashboard", want: []string{"data-i18n=\"label.securityFlow\">安全链路", "提示词注入 Prompt Injection", "最近安全事件"}},
		{name: "events decision filter", path: "/dashboard/events?decision=REDACT", want: []string{"data-i18n=\"page.events\">安全事件", "REDACT", "pii.email.v1"}},
		{name: "events detection filter partial", path: "/dashboard/partials/events?detection_type=PII", want: []string{"events-table", "PII", "pii.email.v1"}},
		{name: "tools", path: "/dashboard/tools", want: []string{"email.send", "PENDING", "/api/approvals/" + approvalID + "/approve"}},
		{name: "playground", path: "/dashboard/playground", want: []string{`data-playground`, `data-i18n="page.playground">安全测试台`, `id="playground-form"`, `data-provider-configured="false"`}},
		{name: "request detail", path: "/dashboard/requests/" + requestID, want: []string{"data-i18n=\"page.request\">请求详情", "pii.email.v1", "INPUT_POLICY"}},
		{name: "tool detail", path: "/dashboard/tools/" + toolID, want: []string{"data-i18n=\"page.tool\">工具详情", "data-i18n=\"table.approval\">审批", approvalID}},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", response.Code, response.Body.String())
			}
			body := response.Body.String()
			for _, want := range test.want {
				if !strings.Contains(body, want) {
					t.Fatalf("response missing %q: %s", want, body)
				}
			}
			for _, forbidden := range []string{"dashboard-sensitive@example.test", "provider-private-response", "fictional-tool-argument"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("dashboard leaked raw value %q", forbidden)
				}
			}
		})
	}
}

func TestDashboardBenchmarkShowsPersistedSafeResults(t *testing.T) {
	handler, _, _, _, _, store := testDashboard(t)
	expected := true
	completed := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	run := benchmark.Run{
		ID: "benchmark_dashboard", DatasetVersion: "benchmark-v1", DatasetHash: "dataset-safe-hash", ConfigHash: "config-safe-hash", ProviderMode: "internal", RandomSeed: 1, AgentGuardVersion: "test", Status: "COMPLETED", StartedAt: completed.Add(-time.Second), CompletedAt: completed, TotalSamples: 3,
		Results: []benchmark.CaseResult{
			{ID: "normal-safe", Category: benchmark.CategoryNormal, ExpectedDetection: boolPointer(false), ExpectedDecision: policy.ActionPass, ActualDecision: policy.ActionPass, Passed: true, Latency: time.Millisecond},
			{ID: "pii-safe", Category: benchmark.CategoryPII, ExpectedDetection: &expected, ExpectedDecision: policy.ActionRedact, ActualDecision: policy.ActionPass, Passed: false, Latency: 2 * time.Millisecond, SafeReason: "decision mismatch"},
			{ID: "tool-safe", Category: benchmark.CategoryTool, ExpectedDecision: policy.ActionApproval, ActualDecision: policy.ActionApproval, Passed: true, Latency: time.Millisecond},
		},
	}
	if err := benchmark.Persist(context.Background(), store.DB(), run); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dashboard/benchmark", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{"benchmark-v1", "data-i18n=\"benchmark.categoryMetrics\">分类指标", "pii-safe", "decision mismatch", "N/A"} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	for _, forbidden := range []string{"raw-secret-value", "private prompt text", "provider-response-contents"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("dashboard leaked raw value %q", forbidden)
		}
	}
}

func boolPointer(value bool) *bool { return &value }

func TestDashboardNotFoundAndStaticAsset(t *testing.T) {
	handler, _, _, _, _, _ := testDashboard(t)
	for _, test := range []struct {
		path string
		code int
	}{
		{path: "/dashboard/requests/missing", code: http.StatusNotFound},
		{path: "/dashboard/static/dashboard.css", code: http.StatusOK},
		{path: "/dashboard/static/dashboard.js", code: http.StatusOK},
	} {
		request := httptest.NewRequest(http.MethodGet, test.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.code {
			t.Fatalf("%s status = %d, want %d", test.path, response.Code, test.code)
		}
	}
}

func TestDashboardLocalizationAndHealthShell(t *testing.T) {
	handler, _, _, _, _, _ := testDashboard(t)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{
		`<html lang="zh-CN">`,
		`data-language="zh"`,
		`data-language="en"`,
		`id="service-health"`,
		`data-provider-mode="unknown"`,
		`src="/dashboard/static/dashboard.js"`,
		`data-i18n="page.overview">总览`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q", want)
		}
	}
	for _, forbidden := range []string{`href="/health"`, "总览 Overview", "安全事件 Security Events", "工具调用与审批 Tool &amp; Approval"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("default Chinese shell contains obsolete mixed or linked content %q", forbidden)
		}
	}

	asset := httptest.NewRecorder()
	handler.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/dashboard/static/dashboard.js", nil))
	if asset.Code != http.StatusOK {
		t.Fatalf("javascript status = %d", asset.Code)
	}
	for _, want := range []string{`localStorage.setItem(storageKey, language)`, `"page.overview": "Overview"`, `"page.playground": "Security Playground"`, `fetch("/health"`, `fetch("/v1/chat/completions"`, `/api/audit/events?request_id=`, `"approval.approve": "Approve"`} {
		if !strings.Contains(asset.Body.String(), want) {
			t.Fatalf("javascript missing %q", want)
		}
	}
}

func TestPlaygroundShowsSafeProviderRuntimeMetadata(t *testing.T) {
	_, _, _, _, _, store := testDashboard(t)
	configured, err := New(store.DB(), "test", Runtime{ProviderMode: "mock", ProviderModel: "mock-model", ProviderConfigured: true})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	configured.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/dashboard/playground", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	for _, want := range []string{`data-provider-mode="mock"`, `data-provider-model="mock-model"`, `data-provider-configured="true"`, `data-i18n="playground.configured">已配置`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q", want)
		}
	}
	for _, forbidden := range []string{"AGENTGUARD_PROVIDER_API_KEY", "Authorization", "fixture-key"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("playground leaked provider configuration %q", forbidden)
		}
	}
}

func TestDashboardApprovalButtonsUseExistingApprovalAPI(t *testing.T) {
	handler, service, _, _, approvalID, _ := testDashboard(t)
	api := tools.NewHandler(service)

	approve := httptest.NewRequest(http.MethodPost, "/api/approvals/"+approvalID+"/approve", nil)
	approveResponse := httptest.NewRecorder()
	api.ServeHTTP(approveResponse, approve)
	if approveResponse.Code != http.StatusOK {
		t.Fatalf("approve status = %d: %s", approveResponse.Code, approveResponse.Body.String())
	}
	conflict := httptest.NewRequest(http.MethodPost, "/api/approvals/"+approvalID+"/approve", nil)
	conflictResponse := httptest.NewRecorder()
	api.ServeHTTP(conflictResponse, conflict)
	if conflictResponse.Code != http.StatusConflict {
		t.Fatalf("second approve status = %d, want 409", conflictResponse.Code)
	}

	_, rejectedApproval, err := service.Submit(context.Background(), tools.Request{ToolName: "database.query", TargetType: "database", Sensitive: true})
	if err != nil || rejectedApproval == nil {
		t.Fatalf("create rejectable approval: %v", err)
	}
	reject := httptest.NewRequest(http.MethodPost, "/api/approvals/"+rejectedApproval.ID+"/reject", nil)
	rejectResponse := httptest.NewRecorder()
	api.ServeHTTP(rejectResponse, reject)
	if rejectResponse.Code != http.StatusOK {
		t.Fatalf("reject status = %d: %s", rejectResponse.Code, rejectResponse.Body.String())
	}

	page := httptest.NewRecorder()
	handler.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "/dashboard/tools", nil))
	if strings.Contains(page.Body.String(), "/api/approvals/"+approvalID+"/approve") {
		t.Fatal("executed approval should no longer render an approval button")
	}
}

func testDashboard(t *testing.T) (*Handler, *tools.Service, string, string, string, *storage.Store) {
	t.Helper()
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(t.TempDir(), "dashboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	recorder := audit.New(store.DB())
	requestID := "req_dashboard"
	created := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	if err := recorder.StartRequest(ctx, audit.Request{ID: requestID, Model: "mock", RequestFingerprint: "safe-fingerprint", InputSummary: "message_count=1", CreatedAt: created}); err != nil {
		t.Fatal(err)
	}
	finding := detection.DetectionResult{ID: "detection_dashboard", SubjectType: detection.SubjectTypeRequest, SubjectID: requestID, DetectionType: detection.DetectionTypePII, RuleID: "pii.email.v1", Score: 0.8, Confidence: 0.95, Evidence: "email match masked", Source: detection.SourceInput, Metadata: map[string]string{"match_count": "1"}, CreatedAt: created}
	if err := recorder.Detection(ctx, finding); err != nil {
		t.Fatal(err)
	}
	decision := policy.Decision{ID: "policy_dashboard", SubjectType: detection.SubjectTypeRequest, SubjectID: requestID, Stage: policy.StageInput, Decision: policy.ActionRedact, PolicyID: "input.pii.redact.v1", Reason: "input detection matched configured policy", RiskScore: 0.8, MatchedRules: []string{"pii.email.v1"}, CreatedAt: created}
	if err := recorder.Decision(ctx, decision); err != nil {
		t.Fatal(err)
	}
	score := 0.8
	for _, event := range []audit.Event{
		{ID: "event_dashboard_policy", EventType: audit.EventInputPolicy, Actor: audit.ActorGateway, Source: "INPUT", RequestID: requestID, DetectionType: "PII", RuleID: "pii.email.v1", Decision: "REDACT", RiskScore: &score, Summary: "input policy decision recorded", CreatedAt: created},
		{ID: "event_dashboard_done", EventType: audit.EventChatCompleted, Actor: audit.ActorGateway, Source: "OUTPUT", RequestID: requestID, Decision: "REDACT", Summary: "chat request completed", CreatedAt: created.Add(time.Second)},
	} {
		if err := recorder.Event(ctx, event); err != nil {
			t.Fatal(err)
		}
	}
	if err := recorder.CompleteRequest(ctx, requestID, audit.RequestCompletion{Status: "COMPLETED", FinalDecision: policy.ActionRedact, DetectionCount: 1, OutputSummary: "content_length=24"}); err != nil {
		t.Fatal(err)
	}
	service := tools.NewService(store.DB(), config.Default().Tools, recorder)
	call, approval, err := service.Submit(ctx, tools.Request{ToolName: "email.send", TargetType: "email", External: true, Arguments: []byte(`{"body":"fictional-tool-argument"}`)})
	if err != nil || approval == nil {
		t.Fatalf("create pending approval: call=%+v approval=%+v err=%v", call, approval, err)
	}
	handler, err := New(store.DB(), "test")
	if err != nil {
		t.Fatal(err)
	}
	return handler, service, requestID, call.ID, approval.ID, store
}
