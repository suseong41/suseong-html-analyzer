package scanner

import "testing"

func noteCount(html string) int { return len(Scan(html).Notes) }

func TestCoverageNotes(t *testing.T) {
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성 — 내용이 보이는 페이지는 경고하지 않는다
		{"평범한페이지", `<html><body><h1>안녕</h1><p>내용</p></body></html>`, 0},
		{"스크립트있어도내용있음", `<body><p>내용</p><script src="/a.js"></script></body>`, 0},
		{"스크립트없는빈페이지", `<html><body><div id="root"></div></body></html>`, 0},
		{"빈문서", ``, 0},
		// 양성 — 셸만 있고 내용은 스크립트가 그린다
		{"SPA셸", `<body><div id="root"></div><script src="/app.js"></script></body>`, 1},
		{"인라인스크립트셸", `<body><div id="app"></div><script>render()</script></body>`, 1},
		{"title은본문아님", `<head><title>대시보드</title></head><body><div id=root></div><script src=/a.js></script></body>`, 1},
		{"noscript는본문아님", `<body><div id=root></div><noscript>JS가 필요합니다</noscript><script src=/a.js></script></body>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := noteCount(c.html); got != c.want {
				t.Errorf("%s → Notes %d개, want %d개", c.html, got, c.want)
			}
		})
	}
}

func TestNotesAreNotFindings(t *testing.T) {
	res := Scan(`<body><div id="root"></div><script src="/app.js"></script></body>`)
	if len(res.Notes) != 1 {
		t.Fatalf("Notes = %d개, want 1개", len(res.Notes))
	}
	if len(res.Findings) != 0 {
		t.Errorf("Findings = %d개, want 0개 — SPA 는 위험이 아니다", len(res.Findings))
	}
}
