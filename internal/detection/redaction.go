package detection

import (
	"sort"
	"strconv"
	"strings"
)

// Redaction records a safe replacement operation, never the original value.
type Redaction struct {
	Replacement string `json:"replacement"`
	StartOffset int    `json:"start_offset"`
	EndOffset   int    `json:"end_offset"`
}

// Redact replaces findings from one text fragment. Overlaps are resolved
// deterministically by earliest offset, then longest match, then rule ID.
func Redact(text string, results []DetectionResult) (string, []Redaction) {
	type candidate struct {
		result DetectionResult
		start  int
		end    int
	}
	candidates := make([]candidate, 0, len(results))
	for _, result := range results {
		start, startErr := strconv.Atoi(result.Metadata["start_offset"])
		end, endErr := strconv.Atoi(result.Metadata["end_offset"])
		if startErr != nil || endErr != nil || start < 0 || end < start || end > len(text) {
			continue
		}
		candidates = append(candidates, candidate{result: result, start: start, end: end})
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].start != candidates[j].start {
			return candidates[i].start < candidates[j].start
		}
		if candidates[i].end != candidates[j].end {
			return candidates[i].end > candidates[j].end
		}
		return candidates[i].result.RuleID < candidates[j].result.RuleID
	})

	var builder strings.Builder
	redactions := make([]Redaction, 0, len(candidates))
	cursor := 0
	for _, candidate := range candidates {
		if candidate.start < cursor {
			continue
		}
		replacement := replacementFor(candidate.result.RuleID)
		builder.WriteString(text[cursor:candidate.start])
		builder.WriteString(replacement)
		redactions = append(redactions, Redaction{Replacement: replacement, StartOffset: candidate.start, EndOffset: candidate.end})
		cursor = candidate.end
	}
	builder.WriteString(text[cursor:])
	return builder.String(), redactions
}

func replacementFor(ruleID string) string {
	switch {
	case strings.HasPrefix(ruleID, "pii.email."):
		return "[REDACTED_EMAIL]"
	case strings.HasPrefix(ruleID, "pii.cn_mobile."):
		return "[REDACTED_PHONE]"
	case strings.HasPrefix(ruleID, "pii.cn_id_card."):
		return "[REDACTED_ID]"
	default:
		return "[REDACTED_SECRET]"
	}
}
