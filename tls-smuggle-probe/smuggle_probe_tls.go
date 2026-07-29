// smuggle_probe_tls.go
//
// TLS-capable HTTP/1.1 request-smuggling parser-deviation probe.
//
// This is the TLS sibling of the plaintext probe: it speaks raw HTTP/1.1 bytes
// to a target and characterises how the target's parser treats ambiguous /
// malformed message framing (Content-Length vs Transfer-Encoding, obfuscated
// TE, duplicate CL, bare-LF line endings). Those parser deviations are the raw
// material for request smuggling when the target sits behind a front-end that
// parses differently.
//
// Over TLS the *vulnerability* is unchanged (framing is parsed after
// decryption), but two things about the *probe* change and are handled here:
//   1. We must wrap the socket in TLS (self-signed certs -> -k / -insecure).
//   2. ALPN may negotiate HTTP/2, whose framing is completely different and to
//      which these HTTP/1.1 payloads do not apply. We PIN ALPN to http/1.1 and
//      loudly warn if the server still forces h2 (that needs an h2 probe).
//
// Usage:
//   go run smuggle_probe_tls.go [flags] <url>
//   go run smuggle_probe_tls.go -k https://localhost:3443
//   go run smuggle_probe_tls.go http://localhost:3000        (plaintext still works)
//
// Flags:
//   -k, -insecure   skip TLS certificate verification (for self-signed certs)
//   -alpn string    comma-separated ALPN protocols to offer (default "http/1.1")
//   -timeout dur    per-request read timeout used for the time-based tests (default 3s)
//   -v              verbose: dump the raw response bytes for every test
package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type target struct {
	scheme string
	host   string // hostname only (for SNI + Host header host part)
	port   string
	tls    *tls.Config
}

type outcome struct {
	firstLine string
	elapsed   time.Duration
	timedOut  bool
	gotData   bool
	err       error
}

type testCase struct {
	name   string
	desc   string
	build  func(hostHeader string) []byte
	interp string
}

func main() {
	insecure := flag.Bool("k", false, "skip TLS certificate verification (self-signed certs)")
	flag.BoolVar(insecure, "insecure", false, "skip TLS certificate verification (self-signed certs)")
	alpn := flag.String("alpn", "http/1.1", "comma-separated ALPN protocols to offer")
	timeout := flag.Duration("timeout", 3*time.Second, "per-request read timeout for time-based tests")
	verbose := flag.Bool("v", false, "dump raw response bytes for every test")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: smuggle_probe_tls [-k] [-alpn p1,p2] [-timeout 3s] [-v] <url>")
		os.Exit(2)
	}
	u, err := url.Parse(flag.Arg(0))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		fmt.Fprintf(os.Stderr, "bad url %q (need http:// or https://)\n", flag.Arg(0))
		os.Exit(2)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	t := target{scheme: u.Scheme, host: host, port: port}
	if u.Scheme == "https" {
		t.tls = &tls.Config{
			InsecureSkipVerify: *insecure, // #nosec G402 -- probe against self-signed local targets
			ServerName:         host,
			NextProtos:         splitCSV(*alpn),
			MinVersion:         tls.VersionTLS12,
		}
	}

	fmt.Println("uWebSockets/HTTP request-smuggling parser-deviation probe (TLS-capable)")
	fmt.Printf("target: %s://%s:%s\n", t.scheme, t.host, t.port)

	// --- TLS handshake + ALPN report (one throwaway connection) ---
	if t.scheme == "https" {
		alpn, err := reportTLS(t)
		if err != nil {
			fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)
			os.Exit(1)
		}
		if alpn == "h2" {
			fmt.Println("\nHTTP/1.1 CL/TE payloads do not apply to an HTTP/2 connection — stopping.")
			fmt.Println("To force HTTP/1.1 instead, offer only that codec:  -alpn http/1.1")
			return
		}
	} else {
		fmt.Println("transport: plaintext HTTP (no TLS)")
	}
	fmt.Println()

	hostHeader := t.host
	if (t.scheme == "https" && t.port != "443") || (t.scheme == "http" && t.port != "80") {
		hostHeader = net.JoinHostPort(t.host, t.port)
	}

	results := make(map[string]outcome)
	for _, tc := range tests() {
		o := probe(t, tc.build(hostHeader), *timeout, *verbose, tc.name)
		results[tc.name] = o
		fmt.Printf("  %-22s %s\n", tc.name, render(o))
	}

	fmt.Println()
	analyse(results)
}

// -------------------------------------------------------------------------
// networking
// -------------------------------------------------------------------------

func dial(t target, connectTO time.Duration) (net.Conn, string, error) {
	addr := net.JoinHostPort(t.host, t.port)
	d := net.Dialer{Timeout: connectTO}
	if t.scheme == "https" {
		c, err := tls.DialWithDialer(&d, "tcp", addr, t.tls)
		if err != nil {
			return nil, "", err
		}
		return c, c.ConnectionState().NegotiatedProtocol, nil
	}
	c, err := d.Dial("tcp", addr)
	return c, "", err
}

func reportTLS(t target) (string, error) {
	c, alpn, err := dial(t, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	cs := c.(*tls.Conn).ConnectionState()
	fmt.Printf("transport: TLS %s, cipher=0x%04x, ALPN=%q\n", tlsVersion(cs.Version), cs.CipherSuite, alpn)
	if alpn == "h2" {
		fmt.Println("  !! WARNING: server negotiated HTTP/2. These HTTP/1.1 CL/TE payloads do NOT apply.")
		fmt.Println("     HTTP/2 has explicit binary framing; test h2-downgrade smuggling instead.")
	} else if alpn == "" {
		fmt.Println("  (no ALPN negotiated -> server will speak HTTP/1.1; payloads apply)")
	} else {
		fmt.Printf("  (ALPN %q -> HTTP/1.1 payloads apply)\n", alpn)
	}
	return alpn, nil
}

// probe sends one raw request on a fresh connection and records whether the
// server produced a response line before the read timeout (fast) or waited for
// more body (timeout) — the core signal for CL-vs-TE inference.
func probe(t target, raw []byte, readTO time.Duration, verbose bool, name string) outcome {
	conn, _, err := dial(t, 5*time.Second)
	if err != nil {
		return outcome{err: err}
	}
	defer conn.Close()

	start := time.Now()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(raw); err != nil {
		return outcome{err: err, elapsed: time.Since(start)}
	}

	_ = conn.SetReadDeadline(time.Now().Add(readTO))
	br := bufio.NewReader(conn)
	line, rerr := br.ReadString('\n')
	elapsed := time.Since(start)

	if verbose {
		fmt.Printf("     [%s] raw request:\n%s\n", name, indent(string(raw)))
		rest, _ := readAll(br, 400)
		fmt.Printf("     [%s] response first bytes:\n%s\n", name, indent(strings.TrimRight(line+rest, "\r\n")))
	}

	if line != "" {
		return outcome{firstLine: strings.TrimRight(line, "\r\n"), elapsed: elapsed, gotData: true}
	}
	if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
		return outcome{timedOut: true, elapsed: elapsed}
	}
	return outcome{err: rerr, elapsed: elapsed}
}

// -------------------------------------------------------------------------
// test payloads
// -------------------------------------------------------------------------

func tests() []testCase {
	return []testCase{
		{
			name: "baseline-get",
			desc: "plain GET",
			build: func(h string) []byte {
				return raw("GET / HTTP/1.1", h, nil, "")
			},
		},
		{
			name: "baseline-post-cl",
			desc: "POST with matching Content-Length",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Content-Length: 5"}, "hello")
			},
		},
		{
			name: "te-chunked",
			desc: "POST Transfer-Encoding: chunked (no CL) — does the parser support chunked request bodies?",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")
			},
		},
		{
			name: "clte-A",
			desc: "CL+TE, chunked body COMPLETE but CL says more. fast=>used TE, timeout=>used CL",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Content-Length: 20", "Transfer-Encoding: chunked"}, "0\r\n\r\n")
			},
			interp: "fast=>TE  timeout=>CL",
		},
		{
			name: "clte-B",
			desc: "CL+TE, chunked body INCOMPLETE but CL complete. fast=>used CL, timeout=>used TE",
			build: func(h string) []byte {
				// after the blank line: "1\r\nA\r\n" = a complete size-1 chunk but no terminator
				return raw("POST / HTTP/1.1", h, []string{"Content-Length: 6", "Transfer-Encoding: chunked"}, "1\r\nA\r\n")
			},
			interp: "fast=>CL  timeout=>TE",
		},
		{
			name: "dup-cl",
			desc: "two conflicting Content-Length headers — RFC says reject",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Content-Length: 5", "Content-Length: 6"}, "hello")
			},
		},
		{
			name: "te-trailing-space",
			desc: "Transfer-Encoding: chunked<space> (obfuscated value)",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Transfer-Encoding: chunked "}, "5\r\nhello\r\n0\r\n\r\n")
			},
		},
		{
			name: "te-space-before-colon",
			desc: "Transfer-Encoding<space>: chunked (obfuscated header name)",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Transfer-Encoding : chunked"}, "5\r\nhello\r\n0\r\n\r\n")
			},
		},
		{
			name: "te-xchunked",
			desc: "Transfer-Encoding: xchunked (unknown coding)",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Transfer-Encoding: xchunked"}, "5\r\nhello\r\n0\r\n\r\n")
			},
		},
		{
			name: "te-double",
			desc: "two Transfer-Encoding headers (identity then chunked)",
			build: func(h string) []byte {
				return raw("POST / HTTP/1.1", h, []string{"Transfer-Encoding: identity", "Transfer-Encoding: chunked"}, "5\r\nhello\r\n0\r\n\r\n")
			},
		},
		{
			name: "bare-lf",
			desc: "headers terminated with bare LF instead of CRLF",
			build: func(h string) []byte {
				// entire request uses \n only
				return []byte("POST / HTTP/1.1\nHost: " + h + "\nContent-Length: 5\nConnection: close\n\nhello")
			},
		},
	}
}

// raw assembles a CRLF HTTP/1.1 request. Always adds Host + Connection: close.
func raw(reqLine, host string, extraHeaders []string, body string) []byte {
	var b strings.Builder
	b.WriteString(reqLine + "\r\n")
	b.WriteString("Host: " + host + "\r\n")
	for _, h := range extraHeaders {
		b.WriteString(h + "\r\n")
	}
	b.WriteString("Connection: close\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// -------------------------------------------------------------------------
// output / analysis
// -------------------------------------------------------------------------

func render(o outcome) string {
	switch {
	case o.err != nil:
		return fmt.Sprintf("ERROR: %v", o.err)
	case o.timedOut:
		return fmt.Sprintf("TIMEOUT (no response in %s — server waited for more body)", o.elapsed.Round(time.Millisecond))
	case o.gotData:
		return fmt.Sprintf("%-42s (%s)", "\""+o.firstLine+"\"", dur(o.elapsed))
	default:
		return "no data / connection closed"
	}
}

func dur(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(100 * time.Microsecond).String()
}

func analyse(r map[string]outcome) {
	fmt.Println("interpretation")
	fmt.Println("--------------")

	// CL vs TE preference from the two complementary time tests.
	a, b := r["clte-A"], r["clte-B"]
	aFast := a.gotData && !a.timedOut
	bFast := b.gotData && !b.timedOut
	switch {
	case is4xx(a) && is4xx(b):
		fmt.Println("• CL+TE: server REJECTS requests carrying both Content-Length and Transfer-Encoding (RFC-compliant, good).")
	case aFast && b.timedOut:
		fmt.Println("• CL+TE: server parses the TRANSFER-ENCODING body (TE-preferred). A CL-preferring front-end would desync (TE.CL).")
	case a.timedOut && bFast:
		fmt.Println("• CL+TE: server parses the CONTENT-LENGTH body (CL-preferred). A TE-preferring front-end would desync (CL.TE).")
	default:
		fmt.Printf("• CL+TE: inconclusive/mixed (A=%s, B=%s). Inspect with -v.\n", short(a), short(b))
	}

	// chunked support
	if tc := r["te-chunked"]; is2xx(tc) {
		fmt.Println("• chunked: server accepts chunked request bodies.")
	} else if tc.timedOut {
		fmt.Println("• chunked: server did NOT complete on a well-formed chunked body (no/partial chunked support).")
	} else {
		fmt.Printf("• chunked: server responded %s to a chunked body.\n", short(r["te-chunked"]))
	}

	// duplicate CL
	if is4xx(r["dup-cl"]) {
		fmt.Println("• duplicate Content-Length: rejected (good).")
	} else {
		fmt.Printf("• duplicate Content-Length: NOT rejected (%s) — smuggling risk with a stricter proxy.\n", short(r["dup-cl"]))
	}

	// obfuscated TE acceptance
	for _, n := range []string{"te-trailing-space", "te-space-before-colon", "te-xchunked", "te-double"} {
		o := r[n]
		verdict := "handled as-is"
		switch {
		case is4xx(o):
			verdict = "rejected (400) — strict"
		case is2xx(o):
			verdict = "ACCEPTED (200) — lenient; deviation risk if a paired proxy disagrees"
		case o.timedOut:
			verdict = "TIMEOUT — parser treated framing differently than expected"
		}
		fmt.Printf("• obfuscated TE [%s]: %s\n", n, verdict)
	}

	// bare LF
	o := r["bare-lf"]
	switch {
	case is2xx(o):
		fmt.Println("• bare-LF line endings: ACCEPTED — lenient; classic smuggling deviation vs CRLF-strict proxies.")
	case is4xx(o):
		fmt.Println("• bare-LF line endings: rejected (good).")
	default:
		fmt.Printf("• bare-LF line endings: %s\n", short(o))
	}

	fmt.Println()
	fmt.Println("note: a single-endpoint probe characterises THIS server's parser. Whether a")
	fmt.Println("deviation is exploitable depends on the front-end it is paired with; TLS does")
	fmt.Println("not change any of the above (framing is parsed after decryption).")
}

// -------------------------------------------------------------------------
// small helpers
// -------------------------------------------------------------------------

func is2xx(o outcome) bool { return o.gotData && strings.Contains(o.firstLine, " 2") && statusClass(o.firstLine, '2') }
func is4xx(o outcome) bool { return o.gotData && (statusClass(o.firstLine, '4') || statusClass(o.firstLine, '5')) }

func statusClass(line string, class byte) bool {
	// line like "HTTP/1.1 200 OK"
	f := strings.Fields(line)
	if len(f) < 2 || len(f[1]) < 1 {
		return false
	}
	return f[1][0] == class
}

func short(o outcome) string {
	if o.timedOut {
		return "timeout"
	}
	if o.err != nil {
		return "error"
	}
	if o.gotData {
		return "\"" + o.firstLine + "\""
	}
	return "closed"
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func indent(s string) string {
	return "        " + strings.ReplaceAll(strings.TrimRight(s, "\r\n"), "\n", "\n        ")
}

func readAll(br *bufio.Reader, max int) (string, error) {
	buf := make([]byte, max)
	n, err := br.Read(buf)
	return string(buf[:n]), err
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}
