package scanner

import (
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// credentialForm(): 토큰이 <input type=password>이고, 열린 <form> 안에 있을 때
// form 시작 태그를 반환.
func credentialForm(ctx *Context, tok tokenizer.Token) (tokenizer.Token, bool) {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "input" {
		return tokenizer.Token{}, false
	}
	if v, ok := tok.Attr("type"); !ok || !strings.EqualFold(strings.TrimSpace(v), "password") {
		return tokenizer.Token{}, false
	}
	return ctx.OpenForm()
}

// 비밀번호가 평문으로 전송될 때.
// A. <input type=password>가 존재,
// B. <form> 안에 있을 때,
// C. 그 폼의 전송이 평문일 때.
func ruleClearTextCredentials(ctx *Context, tok tokenizer.Token) []Finding {
	form, ok := credentialForm(ctx, tok)
	if !ok {
		return nil
	}
	action, _ := form.Attr("action")
	v := normalizeURL(action)

	var why string
	switch {
	case strings.HasPrefix(v, "http://"):
		why = "action=" + action
	case absoluteHost(action) == "" && ctx.Scheme == "http":
		why = "페이지가 http, action 이 상대 경로 (" + action + ")"
	default:
		return nil
	}
	return []Finding{{
		Code: "cleartext-credentials", Class: ClassExfiltration,
		Title:    "비밀번호가 평문으로 전송됨",
		Severity: High, Offset: tok.Offset, Evidence: why,
	}}
}

// 이름은 비밀번호인데 typ이 password가 아닌경우
// 개발자 실수. -Medium
var passwordNameHints = []string{"password", "passwd", "pwd"}

func ruleWeakPasswordField(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "input" {
		return nil
	}
	typ := strings.ToLower(strings.TrimSpace(mustAttr(tok, "type")))
	if typ != "" && typ != "text" {
		return nil // password, hidden, email
	}
	for _, key := range []string{"name", "id", "autocomplete"} {
		val := asciiLower(mustAttr(tok, key))
		if val == "" {
			continue
		}
		for _, hint := range passwordNameHints {
			if strings.Contains(val, hint) {
				return []Finding{{
					Code: "weak-password-field", Class: ClassHardening,
					Title:    "비밀번호 필드의 type 이 password 가 아님",
					Severity: Medium, Offset: tok.Offset,
					Evidence: key + "=" + mustAttr(tok, key) + " type=" + typ,
				}}
			}
		}
	}
	return nil
}

func mustAttr(tok tokenizer.Token, name string) string {
	v, _ := tok.Attr(name)
	return v
}
