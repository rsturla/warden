package proxy

import (
	"io"
	"net/http"
)

var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

func copyBody(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}
