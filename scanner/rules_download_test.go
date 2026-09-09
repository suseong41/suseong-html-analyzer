package scanner

import "testing"

func TestURLPathExt(t *testing.T) {
	cases := []struct{ in, want string }{
		// 호스트를 확장자로 오인하면 안 된다
		{"https://www.jnu.ac.kr", ""},
		{"https://evil.kr", ""},
		{"//cdn.example.com", ""},
		{"https://a.com/", ""},
		// 정상 추출
		{"https://a.com/files/setup.hta", "hta"},
		{"/download/a.scr", "scr"},
		{"a.vbs", "vbs"},
		{"https://a.com/x.aspx?f=1", "aspx"},
		{"https://a.com/x.hta#frag", "hta"},
		{"https://a.com/a.b.c/d.exe", "exe"},
		// 확장자 없음
		{"https://a.com/download", ""},
		{"https://a.com/dir.d/file", ""},
		{"https://a.com/x.", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := urlPathExt(c.in); got != c.want {
			t.Errorf("urlPathExt(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestDangerousDownload(t *testing.T) {
	const code = "dangerous-download"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성
		{"일반링크", `<a href="/board/list.aspx">목록</a>`, 0},
		{"도메인만", `<a href="https://www.jnu.ac.kr">링크</a>`, 0},
		{"설치파일은제외", `<a href="/dl/setup.exe">다운로드</a>`, 0},
		{"jar도제외", `<a href="/dl/app.jar">다운로드</a>`, 0},
		{"href없음", `<a name="top"></a>`, 0},
		{"이미지src", `<img src="/x.scr">`, 0},
		// 양성
		{"hta", `<a href="https://evil.com/inv.hta">청구서</a>`, 1},
		{"scr", `<a href="/files/photo.scr">사진</a>`, 1},
		{"대문자", `<a href="/A.VBS">x</a>`, 1},
		{"쿼리뒤", `<a href="/d/run.bat?v=2">x</a>`, 1},
		{"문자참조우회", `<a href="/d/run&#46;hta">x</a>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}

func TestResourceIPLiteral(t *testing.T) {
	const code = "resource-ip-literal"
	cases := []struct {
		name, html string
		want       int
	}{
		// 음성
		{"도메인스크립트", `<script src="https://cdn.x.com/a.js"></script>`, 0},
		{"상대경로", `<script src="/a.js"></script>`, 0},
		{"IP링크는대상아님", `<a href="http://192.168.0.1/x">링크</a>`, 0},
		{"경로에숫자", `<img src="/img/1.2.3.4/a.png">`, 0},
		// 양성
		{"IP스크립트", `<script src="http://203.0.113.5/a.js"></script>`, 1},
		{"IP이미지", `<img src="//198.51.100.7/a.png">`, 1},
		{"IP스타일시트", `<link rel=stylesheet href="http://192.168.0.1/a.css">`, 1},
		{"IP포트", `<script src="https://203.0.113.5:8443/a.js"></script>`, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countCode(c.html, "https://a.com/", code); got != c.want {
				t.Errorf("%s → %d건, want %d건", c.html, got, c.want)
			}
		})
	}
}
