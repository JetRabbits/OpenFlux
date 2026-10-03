package yandex

import "net/url"

// safeDocURL keeps only scheme and host for logs so document ids, paths,
// query strings, captcha tokens, and retpaths are not emitted.
func safeDocURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "<redacted-url>"
	}
	return u.Scheme + "://" + u.Host
}
