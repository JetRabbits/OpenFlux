package yandex

import (
	"context"
	"net"
	"net/http"
	"time"

	utls "github.com/refraction-networking/utls"
)

func chromeLikeHTTPClient(jar http.CookieJar, timeout time.Duration) *http.Client {
	return &http.Client{
		Jar:     jar,
		Timeout: timeout,
		Transport: &http.Transport{
			DialTLSContext:    chromeLikeDialTLSContext,
			ForceAttemptHTTP2: false,
		},
	}
}

func chromeLikeDialTLSContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	tcpConn, err := dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	config := &utls.Config{
		ServerName: host,
		NextProtos: []string{"http/1.1"},
		MinVersion: utls.VersionTLS12,
	}
	uconn := utls.UClient(tcpConn, config, utls.HelloChrome_Auto)
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	return uconn, nil
}

func setChromeLikeHeaders(req *http.Request, userAgent string) {
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("Accept-Encoding", "identity")
}
