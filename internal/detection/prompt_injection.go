package detection

import (
	"context"
	"regexp"
)

type promptRule struct {
	id         string
	pattern    *regexp.Regexp
	score      float64
	confidence float64
	evidence   string
}

// PromptInjectionDetector is a small, deterministic rule-and-feature detector.
// It detects attempts to control the agent, rather than discussion of attacks.
type PromptInjectionDetector struct {
	directRules     []promptRule
	externalContent *regexp.Regexp
	indirectAction  *regexp.Regexp
}

func NewPromptInjectionDetector() *PromptInjectionDetector {
	commandStart := `(?i)(?:^|[\n。！？.!?][[:space:]]*)(?:请|请你|please[[:space:]]+)?[[:space:]]*`
	return &PromptInjectionDetector{
		directRules: []promptRule{
			{id: "prompt.direct.override.v1", pattern: regexp.MustCompile(commandStart + `(?:ignore|disregard|override|忽略|无视)[^\n。！？.!?]{0,80}(?:previous|prior|above|system|instructions?|rules?|之前|先前|以上|系统|指令|规则)`), score: 0.92, confidence: 0.95, evidence: "instruction-override command detected"},
			{id: "prompt.direct.system_exfiltration.v1", pattern: regexp.MustCompile(commandStart + `(?:show|display|reveal|leak|print|output|显示|展示|泄露|输出)[^\n。！？.!?]{0,80}(?:system[[:space:]]+prompt|hidden[[:space:]]+instructions?|internal[[:space:]]+prompt|系统提示词|隐藏指令|内部提示词)`), score: 0.92, confidence: 0.94, evidence: "system-prompt exfiltration command detected"},
			{id: "prompt.direct.safety_bypass.v1", pattern: regexp.MustCompile(commandStart + `(?:bypass|skip|disable|do[[:space:]]+not[[:space:]]+follow|绕过|跳过|禁用|不要遵守)[^\n。！？.!?]{0,80}(?:safety|security|policy|check|guardrail|安全|策略|检查|限制)`), score: 0.91, confidence: 0.93, evidence: "safety-control bypass command detected"},
			{id: "prompt.direct.secret_exfiltration.v1", pattern: regexp.MustCompile(commandStart + `(?:show|display|reveal|leak|output|显示|展示|泄露|输出)[^\n。！？.!?]{0,80}(?:hidden[[:space:]]+secret|environment[[:space:]]+variables?|internal[[:space:]]+config|隐藏密钥|环境变量|内部配置)`), score: 0.92, confidence: 0.94, evidence: "sensitive-data exfiltration command detected"},
			{id: "prompt.direct.role_override.v1", pattern: regexp.MustCompile(commandStart + `(?:you[[:space:]]+are[[:space:]]+now|act[[:space:]]+as|enter|进入|切换到|改变|覆盖)[^\n。！？.!?]{0,80}(?:developer[[:space:]]+mode|unrestricted|new[[:space:]]+role|角色|开发者模式|不受限制)`), score: 0.75, confidence: 0.82, evidence: "role-override instruction detected"},
		},
		externalContent: regexp.MustCompile(`(?i)(?:web[[:space:]]+page|document|external[[:space:]]+content|quoted[[:space:]]+content|网页内容|文档内容|外部内容|以下是.*(?:网页|文档))`),
		indirectAction:  regexp.MustCompile(`(?i)(?:ignore|disregard|override|忽略|无视)[^\n]{0,100}(?:task|instructions?|rules?|任务|指令|规则)|(?:send|exfiltrate|发送|传出)[^\n]{0,100}(?:data|information|数据|信息)`),
	}
}

func (d *PromptInjectionDetector) Detect(_ context.Context, input Input) []DetectionResult {
	var results []DetectionResult
	for _, rule := range d.directRules {
		for _, match := range rule.pattern.FindAllStringIndex(input.Text, -1) {
			results = append(results, NewResult(input, DetectionTypePromptInjection, rule.id, rule.score, rule.confidence, rule.evidence, match[0], match[1]))
		}
	}
	if d.externalContent.MatchString(input.Text) && d.indirectAction.MatchString(input.Text) {
		match := d.indirectAction.FindStringIndex(input.Text)
		results = append(results, NewResult(input, DetectionTypePromptInjection, "prompt.indirect.instruction_override.v1", 0.95, 0.93, "external-content instruction override detected", match[0], match[1]))
	}
	if len(results) >= 2 {
		results = append(results, NewResult(input, DetectionTypePromptInjection, "prompt.direct.combined.v1", 0.98, 0.97, "multiple prompt-injection command patterns detected", 0, 0))
	}
	return results
}

var _ Detector = (*PromptInjectionDetector)(nil)
