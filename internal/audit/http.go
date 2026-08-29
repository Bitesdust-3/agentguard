package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
)

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/api/audit/events" {
		http.NotFound(w, r)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 || value > 100 {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = value
	}
	items, err := s.List(r.Context(), Filter{EventType: r.URL.Query().Get("event_type"), Decision: r.URL.Query().Get("decision"), DetectionType: r.URL.Query().Get("detection_type"), RequestID: r.URL.Query().Get("request_id"), ToolCallID: r.URL.Query().Get("tool_call_id"), Limit: limit})
	if err != nil {
		http.Error(w, "audit query failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(struct {
		Items []Event `json:"items"`
	}{items})
}
