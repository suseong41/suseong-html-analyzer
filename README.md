# suseong-html-analyzer

![CI](https://github.com/suseong41/suseong-html-analyzer/actions/workflows/ci.yml/badge.svg)

HTML을 파싱해 **XSS·피싱·리소스 위험**을 찾아내는 정적 보안 스캐너 (Go).
외부 의존성 없이 표준 라이브러리만으로 동작한다.

정적 분석 도구다. "패턴이 존재한다"는 것을 보고할 뿐,
공격자가 그 값을 실제로 제어하는지까지는 증명하지 않는다.

---

### 기능

WHATWG 토크나이저(브라우저와 동일하게 해석)를 만들고, 그 위에 규칙을 얹는다.

* **파싱** — `<script>`/`<style>` 원시 텍스트, 문자 참조 디코딩, 주석·DOCTYPE,
  script escaped state, 열린 요소 스택까지 브라우저와 동일하게 처리
* **탐지 규칙 10종** (심각도별)

| 심각도 | 분류 | 규칙 | 내용 |
  |---|---|---|---|
  | HIGH | exfiltration | `exfil-channel` | 스크립트·폼이 외부 메시징 API로 전송 |
  | HIGH | exfiltration | `cross-origin-password-form` | 비밀번호 폼이 외부 도메인으로 전송 |
  | HIGH | exfiltration | `form-action-ip` | 폼이 IP 주소로 직접 전송 |
  | HIGH | execution | `webshell-signature` | 스크립트 내 웹셸 시그니처 (c99, ByroeNet 등) |
  | HIGH | execution | `meta-refresh-scheme` | `meta refresh` 가 `data:`/`javascript:` 로 이동 |
  | HIGH | execution | `data-uri-document` | 실행 가능한 `data:` URI 를 iframe/object/script 에 삽입 |
  | HIGH | origin | `base-href-external` | `<base href>` 가 외부 도메인 — 모든 상대 URL이 그쪽으로 |
  | MEDIUM | execution | `javascript-url` | `javascript:` URL (문자 참조 우회 포함) |
  | MEDIUM | origin | `iframe-sandbox-escape` | `allow-scripts` 와 `allow-same-origin` 동시 허용 |
  | MEDIUM | supply-chain | `sri-missing` | 외부 리소스에 `integrity` 없음 |
  | MEDIUM | supply-chain | `mixed-content` | HTTPS 페이지의 `http://` 하위 리소스 |
  | MEDIUM | evasion | `obfuscated-eval` | `eval()` + 디코더(`atob` 등) 조합 |
  | LOW | evasion | `zero-width` | 제로폭 문자 난독화 |
  | LOW | hardening | `inline-handler` | 인라인 이벤트 핸들러 (`onclick` 등) |
  | INFO | hardening | `target-blank-no-rel` | `target=_blank` 에 `rel=noopener` 없음 |



---

### 사용 방법

```sh
go build .

# 파일만 스캔
./suseong-html-analyzer page.html

# URL을 주면 출처 기반 규칙(외부 도메인 폼·혼합 콘텐츠·SRI)이 켜진다
./suseong-html-analyzer page.html https://example.com/

# 최소 심각도로 거르기 · 통계 함께 보기
./suseong-html-analyzer -min medium page.html https://example.com/
./suseong-html-analyzer -stats page.html

# 분류로 거르기
./suseong-html-analyzer -class exfiltration page.html https://example.com/
```

출력은 `파일:줄:칸: 심각도 [규칙] 근거` 형식이라 에디터에서 바로 점프할 수 있다.

```
page.html:12:8: HIGH   [exfil-channel] action=https://api.telegram.org/...
```
발견과 별개로 **분석의 한계**를 stderr 에 보고한다.
SPA 셸처럼 내용을 스크립트가 그리는 페이지가 그렇다.
이것은 위험이 아니라 **우리가 보지 못한 것**이므로 종료 코드에 영향을 주지 않는다.

**종료 코드** — `0` 발견 없음 · `1` 발견 있음 · `2` 사용법/입출력 오류.
CI에서 `-min high` 로 걸어 실패시킬 수 있다.

---

### 빌드 · 테스트

* Go 1.24 이상, 외부 의존성 없음

```sh
go test ./...          # 단위 테스트 + 퍼즈 씨앗
go vet ./...

# 퍼징 (파서·규칙의 크래시/무한루프 탐색)
go test ./tokenizer -run '^$' -fuzz FuzzTokenizer -fuzztime 1m
```