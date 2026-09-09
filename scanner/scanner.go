package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

type Severity int

// Context: 모든 규칙이 공유하는 읽기 전용 정보
type Context struct {
	URL    string
	Scheme string
	Domain string
	stack  openStack
}

// Rule: 토큰을 하나씩 보고 발견을 돌려줌.
type Rule interface {
	Check(ctx *Context, tok tokenizer.Token) []Finding
}

// finisher: 입력이 끝났을 때 마무리가 필요한 규칙만 구현.
type finisher interface{ Finish(ctx *Context) []Finding }

// ruleFunc: 상태 없는 함수를 Rule로 만들어 줌. || 어뎁터
type ruleFunc func(ctx *Context, tok tokenizer.Token) []Finding

func (f ruleFunc) Check(ctx *Context, tok tokenizer.Token) []Finding {
	return f(ctx, tok)
}

const (
	Info Severity = iota
	Low
	Medium
	High
)

// newRules(): 스캔마다 새 규칙 집합 생성.
func newRules() []Rule {
	return []Rule{
		ruleFunc(ruleInlineHandler),
		ruleFunc(ruleJavaScriptURL),
		ruleFunc(ruleZeroWidth),
		ruleFunc(ruleCrossOriginPasswordForm),
		ruleFunc(ruleMixedContent),
		ruleFunc(ruleSubresourceIntegrity),
		&targetBlankRule{},
		ruleFunc(ruleWebShellSignature),
		ruleFunc(ruleExfilChannel),
		ruleFunc(ruleObfuscateEval),
		ruleFunc(ruleMetaRefreshScheme),
		ruleFunc(ruleBaseHrefExternal),
		ruleFunc(ruleIframeSandboxEscape),
		ruleFunc(ruleFormActionIP),
		ruleFunc(ruleDataURIDocument),
	}
}

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Low:
		return "LOW"
	case Medium:
		return "MEDIUM"
	case High:
		return "HIGH"
	}
	return "?"
}

// Finding 정의하고 []Finding 슬라이스 사용.
type Finding struct {
	Code     string
	Title    string
	Severity Severity
	Offset   int    // Rule
	Line     int    // Scan()
	Col      int    // Scan()
	Evidence string // 원본
}

type Result struct {
	Findings []Finding
	Notes    []string
	Tokens   map[tokenizer.TokenType]int
	Tags     map[string]int
}

func Scan(src string) Result { return ScanURL(src, "") }

func ScanURL(src, pageURL string) Result {
	z := tokenizer.New(src)
	ctx := &Context{URL: pageURL, Scheme: schemeOf(pageURL), Domain: domainOf(pageURL)}
	rules := newRules()
	var cov coverage

	res := Result{
		Tokens: map[tokenizer.TokenType]int{},
		Tags:   map[string]int{},
	}

	for {
		tok := z.Next()
		if tok.Type == tokenizer.ErrToken {
			break
		}
		res.Tokens[tok.Type]++

		switch tok.Type {
		case tokenizer.StartTagToken:
			res.Tags[tok.Name]++
			ctx.stack.start(tok)
		case tokenizer.EndTagToken:
			ctx.stack.end(tok.Name)
		}

		cov.observe(ctx, tok)

		for _, r := range rules {
			res.Findings = append(res.Findings, r.Check(ctx, tok)...)
		}
	}

	for _, r := range rules {
		if f, ok := r.(finisher); ok {
			res.Findings = append(res.Findings, f.Finish(ctx)...)
		}
	}

	for i := range res.Findings {
		res.Findings[i].Line, res.Findings[i].Col = z.Position(res.Findings[i].Offset)
	}

	res.Notes = cov.notes()

	return res
}

// absoluteHost(): URL이 호스트를 명시할 때 반환.
// 상대 경로("/x", "./x")이거나 호스트를 뽑을 수 없으면 "" 반환.
func absoluteHost(rawURL string) string {
	v := normalizeURL(rawURL)
	if !strings.HasPrefix(v, "http://") &&
		!strings.HasPrefix(v, "https://") &&
		!strings.HasPrefix(v, "//") {
		return "" // 상대 경로 → 같은 출처
	}
	return domainOf(v)
}

// domainOf(): URL에서 실제 접속 대상 호스트 추출.
func domainOf(rawURL string) string {
	s := strings.TrimSpace(rawURL)
	if i := strings.Index(s, "://"); 0 <= i {
		s = s[i+3:]
	} else if strings.HasPrefix(s, "//") {
		s = s[2:]
	}
	if i := strings.IndexAny(s, "/?#"); 0 <= i {
		s = s[:i]
	}
	if i := strings.LastIndex(s, "@"); 0 <= i { // suseong.com@naver.com -> naver.com
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, ":"); 0 <= i {
		s = s[:i]
	}
	return strings.ToLower(s)
}

// In Element, OpenForm 규칙으로만 접근. 스택 직접 건들지 않음.
// InElement: 현재 열려 있는 조상 중 name이 있는지 확인.
func (c *Context) InElement(name string) bool { return c.stack.has(name) }

// OpenForm(): 지금 유효한 <form> 시작 태그 반환
func (c *Context) OpenForm() (tokenizer.Token, bool) {
	if c.stack.form == nil {
		return tokenizer.Token{}, false
	}
	return *c.stack.form, true
}

// schemeOf(): URL의 scheme을 소문자로
func schemeOf(rawURL string) string {
	if i := strings.Index(rawURL, "://"); 0 <= i {
		return strings.ToLower(strings.TrimSpace(rawURL[:i]))
	}
	return ""
}

// ParseSeverity(): medium -> Severity로 변경
func ParseSeverity(name string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "info":
		return Info, true
	case "low":
		return Low, true
	case "medium", "med":
		return Medium, true
	case "high":
		return High, true
	}
	return Info, false
}
