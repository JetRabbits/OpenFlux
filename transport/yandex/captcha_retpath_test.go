package yandex

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func captchaHTML(t *testing.T, action string) []byte {
	t.Helper()
	ssr := map[string]interface{}{
		"uniqueKey": "test-key",
		"action":    action,
		"pow": map[string]interface{}{
			"complexity": 0,
			"prefix":     "00",
		},
		"timestamp": int64(1),
	}
	raw, err := json.Marshal(ssr)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(raw)
	return []byte(`<html><script>window.__SSR_DATA__ = JSON.parse(atob("` + encoded + `"))</script><form id="tmgrdfrend-form" action="` + action + `"></form></html>`)
}

func withSolveCaptchaFn(t *testing.T, fn func(string, http.CookieJar, string) (string, error)) {
	t.Helper()
	original := solveCaptchaFn
	solveCaptchaFn = fn
	t.Cleanup(func() { solveCaptchaFn = original })
}

func runFetchDocInfoForTest(docURL string) error {
	tr := &YandexDocsTransport{url: docURL}
	_, err := tr.fetchDocInfo(docURL, "0000000001")
	return err
}

func runVolgaAuthorizeForTest(docURL string) error {
	jar, _ := cookiejar.New(nil)
	_, err := authorizeWithJar(docURL, jar)
	return err
}

func TestCaptchaRetpathContinuesFromRetpath(t *testing.T) {
	for name, run := range map[string]func(string) error{
		"ydocs": runFetchDocInfoForTest,
		"volga": runVolgaAuthorizeForTest,
	} {
		t.Run(name, func(t *testing.T) {
			var docRequests atomic.Int32
			var retpathRequests atomic.Int32
			var solveCalls atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/doc":
					docRequests.Add(1)
					http.Redirect(w, r, "/showcaptchafast", http.StatusFound)
				case "/edit/d/retpath":
					retpathRequests.Add(1)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("<html>retpath</html>"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			withSolveCaptchaFn(t, func(string, http.CookieJar, string) (string, error) {
				solveCalls.Add(1)
				return srv.URL + "/edit/d/retpath", nil
			})

			_ = run(srv.URL + "/doc")

			if got := solveCalls.Load(); got != 1 {
				t.Fatalf("solver calls = %d, want 1", got)
			}
			if got := docRequests.Load(); got != 1 {
				t.Fatalf("original doc requests = %d, want 1", got)
			}
			if got := retpathRequests.Load(); got != 1 {
				t.Fatalf("retpath requests = %d, want 1", got)
			}
		})
	}
}

func TestCaptchaRepeatedShowcaptchafastReturnsSentinelWithoutSecondSolve(t *testing.T) {
	for name, run := range map[string]func(string) error{
		"ydocs": runFetchDocInfoForTest,
		"volga": runVolgaAuthorizeForTest,
	} {
		t.Run(name, func(t *testing.T) {
			var solveCalls atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/doc", "/after-solve":
					http.Redirect(w, r, "/showcaptchafast", http.StatusFound)
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			withSolveCaptchaFn(t, func(string, http.CookieJar, string) (string, error) {
				solveCalls.Add(1)
				return srv.URL + "/after-solve", nil
			})

			err := run(srv.URL + "/doc")
			if !errors.Is(err, ErrCaptchaRequired) {
				t.Fatalf("expected ErrCaptchaRequired, got %v", err)
			}
			if got := solveCalls.Load(); got != 1 {
				t.Fatalf("solver calls = %d, want 1", got)
			}
		})
	}
}

func TestCaptchaSmartCaptchaAndPassportSentinels(t *testing.T) {
	for _, tc := range []struct {
		name string
		loc  string
		want error
	}{
		{name: "smartcaptcha", loc: "/showcaptcha?cc=1&mt=secret", want: ErrCaptchaRequired},
		{name: "passport", loc: "/passport.yandex/auth", want: ErrLoginRequired},
	} {
		for transportName, run := range map[string]func(string) error{
			"ydocs": runFetchDocInfoForTest,
			"volga": runVolgaAuthorizeForTest,
		} {
			t.Run(tc.name+"/"+transportName, func(t *testing.T) {
				srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/doc" {
						http.Redirect(w, r, tc.loc, http.StatusFound)
						return
					}
					http.NotFound(w, r)
				}))
				defer srv.Close()

				err := run(srv.URL + "/doc")
				if !errors.Is(err, tc.want) {
					t.Fatalf("expected %v, got %v", tc.want, err)
				}
			})
		}
	}
}

func TestCaptchaEmptyRetpathFallsBackToOriginalURL(t *testing.T) {
	for name, run := range map[string]func(string) error{
		"ydocs": runFetchDocInfoForTest,
		"volga": runVolgaAuthorizeForTest,
	} {
		t.Run(name, func(t *testing.T) {
			var docRequests atomic.Int32
			var solveCalls atomic.Int32

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/doc":
					if docRequests.Add(1) == 1 {
						http.Redirect(w, r, "/showcaptchafast", http.StatusFound)
						return
					}
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("<html>fallback</html>"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			withSolveCaptchaFn(t, func(string, http.CookieJar, string) (string, error) {
				solveCalls.Add(1)
				return "", nil
			})

			_ = run(srv.URL + "/doc")

			if got := solveCalls.Load(); got != 1 {
				t.Fatalf("solver calls = %d, want 1", got)
			}
			if got := docRequests.Load(); got != 2 {
				t.Fatalf("original doc requests = %d, want 2", got)
			}
		})
	}
}

func TestCaptchaRelativeLocationResolvesAndWalkContinues(t *testing.T) {
	for name, run := range map[string]func(string) error{
		"ydocs": runFetchDocInfoForTest,
		"volga": runVolgaAuthorizeForTest,
	} {
		t.Run(name, func(t *testing.T) {
			var retpathRequests atomic.Int32
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/doc":
					http.Redirect(w, r, srv.URL+"/showcaptchafast", http.StatusFound)
				case "/showcaptchafast":
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(captchaHTML(t, srv.URL+"/checkcaptchafast"))
				case "/checkcaptchafast":
					http.Redirect(w, r, "/edit/d/xyz", http.StatusFound)
				case "/edit/d/xyz":
					retpathRequests.Add(1)
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("<html>retpath</html>"))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			_ = run(srv.URL + "/doc")

			if got := retpathRequests.Load(); got != 1 {
				t.Fatalf("/edit/d/xyz requests = %d, want 1", got)
			}
		})
	}
}

func TestSolveCaptchaAbsoluteLocationPassesThroughUnchanged(t *testing.T) {
	jar, _ := cookiejar.New(nil)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/doc":
			http.Redirect(w, r, srv.URL+"/showcaptchafast", http.StatusFound)
		case "/showcaptchafast":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(captchaHTML(t, srv.URL+"/checkcaptchafast"))
		case "/checkcaptchafast":
			http.Redirect(w, r, srv.URL+"/edit/d/absolute", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	retpath, err := solveCaptcha(srv.URL+"/doc", jar, "test-agent")
	if err != nil {
		t.Fatalf("solveCaptcha returned error: %v", err)
	}
	want := srv.URL + "/edit/d/absolute"
	if retpath != want {
		t.Fatalf("retpath = %q, want %q", retpath, want)
	}
}
