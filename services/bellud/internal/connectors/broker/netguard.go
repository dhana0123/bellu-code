package broker

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// metadataAddrs are cloud metadata endpoints that are not link-local.
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("192.0.0.192"),
}

var imdsAddrs = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
}

var errBlockedAddr = errors.New("broker: destination address is not allowed")

// blockedIP reports loopback, link-local, unspecified, multicast and metadata
// addresses. It is applied to the address actually being dialed, after DNS
// resolution, so rebinding cannot bypass it.
func blockedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return true
		}
	}
	return false
}

func controlFor(allowIMDS bool) func(network, address string, _ syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return errBlockedAddr
		}
		ip := ap.Addr().Unmap()
		if allowIMDS {
			// The ambient IMDS client may reach only the metadata service.
			for _, m := range imdsAddrs {
				if ip == m {
					return nil
				}
			}
			return errBlockedAddr
		}
		if blockedIP(ip) {
			return errBlockedAddr
		}
		return nil
	}
}

func newTransport(allowIMDS bool) *http.Transport {
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: controlFor(allowIMDS)}
	return &http.Transport{
		Proxy:                 nil, // a proxy would bypass the dial guard
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
	}
}

// imdsTransport restricts a client to GET/PUT on /latest/ at the IMDS address.
type imdsTransport struct{ inner http.RoundTripper }

func (t imdsTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := req.URL.Hostname()
	ip, err := netip.ParseAddr(host)
	ok := err == nil
	if ok {
		ok = false
		for _, m := range imdsAddrs {
			if ip.Unmap() == m {
				ok = true
			}
		}
	}
	if !ok || req.URL.Scheme != "http" || !strings.HasPrefix(req.URL.Path, "/latest/") ||
		(req.Method != http.MethodGet && req.Method != http.MethodPut) {
		return nil, &BlockedError{Reason: "host_blocked", Violated: "host"}
	}
	return t.inner.RoundTrip(req)
}
