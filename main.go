package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/suseong41/suseong-html-analyzer/scanner"
)

// map: [키]값{}
// Printf - 표준 출력 | Fprintf - 원하는 파일에 출력

func main() { os.Exit(run()) }

func usage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "사용법: %s [옵션] <htmlfile> [url]\n\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintf(out, "\n종료 코드: 0-발견 없음 1-발견 있음 2-사용법/입출력 오류")
}

func run() int {
	flag.Usage = usage
	minName := flag.String("min", "info", "최소 심각도 (info|low|medium|high)")
	showStats := flag.Bool("stats", false, "토큰·태그 통계도 출력")
	flag.Parse()

	if n := flag.NArg(); n < 1 || 2 < n {
		flag.Usage()
		return 2
	}
	min, ok := scanner.ParseSeverity(*minName)
	if !ok {
		fmt.Fprintf(os.Stderr, "알 수 없는 심각도: %q\n", *minName)
		return 2
	}

	path, pageURL := flag.Arg(0), flag.Arg(1)
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	res := scanner.ScanURL(string(data), pageURL)

	var findings []scanner.Finding
	for _, f := range res.Findings {
		if min <= f.Severity {
			findings = append(findings, f)
		}
	}
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[j].Severity < findings[i].Severity
	})

	for _, f := range findings {
		fmt.Printf("%s:%d:%d: %-6s [%s] %s\n", path, f.Line, f.Col, f.Severity, f.Code, f.Evidence)
	}

	if *showStats {
		printStats(res)
	}
	fmt.Fprintf(os.Stderr, "\n%s - 발견 %d건\n", path, len(findings))

	for _, n := range res.Notes {
		fmt.Fprintf(os.Stderr, "참고: %s\n", n)
	}

	if len(findings) == 0 {
		return 0
	}
	return 1
}

func printStats(res scanner.Result) {
	out := os.Stderr
	fmt.Fprintf(out, "\n토큰: %v\n", res.Tokens)
	names := make([]string, 0, len(res.Tags))
	for n := range res.Tags {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return res.Tags[names[j]] < res.Tags[names[i]] })
	fmt.Fprintln(out, "태그별 (상위 10)")
	for i, n := range names {
		if 10 <= i {
			break
		}
		fmt.Fprintf(out, " %-12s %d\n", n, res.Tags[n])
	}
}
