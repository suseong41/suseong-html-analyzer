package scanner

import (
	"fmt"
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// isSubresource(): 브라우저가 자동으로 가져오는 리소스인 속성인지 확인.
func isSubresource(tag, attr string) bool {
	switch attr {
	case "src", "srcset", "poster", "data":
		return true
	case "href":
		return tag == "link" // <link rel=stylesheet>
	case "action", "formaction":
		return true
	}
	return false
}

func ruleSubresourceIntegrity(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	var url string
	switch tok.Name {
	case "script":
		url, _ = tok.Attr("src")
	case "link":
		rel, _ := tok.Attr("rel")
		if !strings.EqualFold(strings.TrimSpace(rel), "stylesheet") {
			return nil
		}
		url, _ = tok.Attr("href")
	default:
		return nil
	}
	if url == "" {
		return nil // inline
	}
	d := absoluteHost(url)
	if d == "" || d == ctx.Domain {
		return nil // 자기 도메인
	}
	if _, ok := tok.Attr("integrity"); ok {
		return nil
	}
	return []Finding{{
		Code: "sri-missing", Class: ClassSupplyChain, Title: "외부 리소스에 integrity 없음", Severity: Medium,
		Offset: tok.Offset, Evidence: "<" + tok.Name + "> " + d,
	}}
}

func ruleMixedContent(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken {
		return nil
	}
	var out []Finding
	for _, a := range tok.Attrs {
		if !isSubresource(tok.Name, a.Name) {
			continue
		}
		if !strings.HasPrefix(normalizeURL(a.Value), "http://") {
			continue
		}
		sev, title := Info, "평문 HTTP 리소스"
		if ctx.Scheme == "https" {
			sev, title = Medium, "혼합 콘텐츠 (HTTPS 페이지의 http:// 리소스)"
		}
		out = append(out, Finding{
			Code: "mixed-content", Class: ClassSupplyChain, Title: title, Severity: sev,
			Offset:   a.Offset,
			Evidence: "<" + tok.Name + " " + a.Name + "=" + a.Value + ">",
		})
	}
	return out
}

// targetBlankRule: 집계용
type targetBlankRule struct {
	count    int
	firstOff int
	firstURL string
}

func (r *targetBlankRule) Check(ctx *Context, tok tokenizer.Token) []Finding {
	if tok.Type != tokenizer.StartTagToken || tok.Name != "a" {
		return nil
	}
	if v, _ := tok.Attr("target"); !strings.EqualFold(strings.TrimSpace(v), "_blank") {
		return nil
	}
	rel, _ := tok.Attr("rel")
	rel = strings.ToLower(rel)
	if strings.Contains(rel, "noopener") || strings.Contains(rel, "noreferrer") {
		return nil
	}
	r.count++
	if r.count == 1 {
		r.firstOff = tok.Offset
		r.firstURL, _ = tok.Attr("href")
	}
	return nil
}

func (r *targetBlankRule) Finish(ctx *Context) []Finding {
	if r.count == 0 {
		return nil
	}
	return []Finding{{
		Code: "target-blank-no-rel", Class: ClassHardening, Title: "target=_blank 에 rel=noopener 없음", Severity: Info,
		Offset:   r.firstOff,
		Evidence: fmt.Sprintf("%d곳 (첫 위치: %s). 2021년 이후 브라우저는 기본 차단", r.count, r.firstURL),
	}}
}
