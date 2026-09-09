package scanner

import (
	"fmt"
	"strings"

	"github.com/suseong41/suseong-html-analyzer/tokenizer"
)

// coverage는 스캔이 페이지를 얼마나 볼 수 있는지 추적.
// 못 보는 것을 확인.
type coverage struct {
	visibleText int
	scripts     int
}

func (c *coverage) observe(ctx *Context, tok tokenizer.Token) {
	switch tok.Type {
	case tokenizer.StartTagToken:
		if tok.Name == "script" {
			c.scripts++
		}
	case tokenizer.TextToken:
		// 사람 눈에 보이는 텍스트만
		if tok.Raw || ctx.InElement("title") || ctx.InElement("textarea") || ctx.InElement("noscript") {
			return
		}
		c.visibleText += len(strings.TrimSpace(tok.Data))
	}
}

func (c *coverage) notes() []string {
	if c.scripts == 0 || 0 < c.visibleText {
		return nil
	}
	return []string{fmt.Sprintf(
		"본문 텍스트가 없고 스크립트가 %d개입니다. 내용이 실행 시점에 생성되므로 "+
			"정적 분석 결과가 이 페이지 전체를 대표하지 않습니다.", c.scripts)}
}
