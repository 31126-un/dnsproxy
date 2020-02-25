package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestFastestAddr(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.allowICMP = false
	up1 := &testUpstream{}

	a := new(dns.A)
	a.Hdr.Rrtype = dns.TypeA
	a.Hdr.Name = "test.org."
	a.A = net.ParseIP("127.0.0.1")
	a.Hdr.Ttl = 60
	up1.aResp = a

	a.A = net.ParseIP("127.0.0.2")
	up1.a2Resp = a

	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, up, err := f.exchangeFastest(req, ups)
	assert.True(t, err == nil)
	assert.True(t, up == up1)
	assert.True(t, resp != nil)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "127.0.0.1" || ip == "127.0.0.2")
}
