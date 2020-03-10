package proxy

import (
	"net"
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func createARec(host, ip string) *dns.A {
	a := new(dns.A)
	a.Hdr.Rrtype = dns.TypeA
	a.Hdr.Name = host
	a.A = net.ParseIP(ip)
	a.Hdr.Ttl = 60
	return a
}

func TestFastestAddr(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.allowICMP = false
	f.tcpPort = 8081
	up1 := &testUpstream{}

	// start listening TCP port on 127.0.0.2
	addr := net.TCPAddr{
		IP:   net.ParseIP("127.0.0.2"),
		Port: int(f.tcpPort),
	}
	lisn, err := net.ListenTCP("tcp4", &addr)
	if err != nil {
		log.Info("skipping test: %s", err)
		return
	}
	defer lisn.Close()

	// add the 1st A response record
	up1.aResp = createARec("test.org.", "127.0.0.1")

	// add the 2nd A response record
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.2"))

	ups := []upstream.Upstream{up1}
	req := createHostTestMessage("test.org")
	resp, up, err := f.exchangeFastest(req, ups)
	assert.True(t, err == nil)
	assert.True(t, up == up1)
	assert.True(t, resp != nil)
	ip := resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "127.0.0.2")

	lisn.Close() // stop server on 127.0.0.2
	// listen on 127.0.0.3
	addr = net.TCPAddr{
		IP:   net.ParseIP("127.0.0.3"),
		Port: int(f.tcpPort),
	}
	lisn, err = net.ListenTCP("tcp4", &addr)
	if err != nil {
		log.Info("skipping test: %s", err)
		return
	}
	defer lisn.Close()

	// add the 3rd A response record
	up1.aRespArr = append(up1.aRespArr, createARec("test.org.", "127.0.0.3"))

	// 127.0.0.2 from cache; or 127.0.0.3 from tcp-connection
	resp, up, err = f.exchangeFastest(req, ups)
	ip = resp.Answer[0].(*dns.A).A.String()
	assert.True(t, ip == "127.0.0.2" || ip == "127.0.0.3")
}

func TestFastestAddrCache(t *testing.T) {
	f := FastestAddr{}
	f.Init()
	f.allowICMP = false
	f.tcpPort = 8081
	up1 := &testUpstream{}

	ent := cacheEntry{
		status:      0,
		latencyMsec: 111,
	}
	f.cacheAdd(&ent, net.ParseIP("1.1.1.1"))
	ent = cacheEntry{
		status:      0,
		latencyMsec: 222,
	}
	f.cacheAdd(&ent, net.ParseIP("2.2.2.2"))
	replies := []upstream.ExchangeAllResult{
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
		upstream.ExchangeAllResult{
			Resp:     &dns.Msg{},
			Upstream: up1,
		},
	}
	replies[0].Resp.Answer = append(replies[0].Resp.Answer, createARec("test.org.", "2.2.2.2"))
	replies[1].Resp.Answer = append(replies[1].Resp.Answer, createARec("test.org.", "1.1.1.1"))
	replies[2].Resp.Answer = append(replies[2].Resp.Answer, createARec("test.org.", "3.3.3.3"))
	result := f.getFromCache("test.org.", replies)
	assert.True(t, result.ip.String() == "1.1.1.1")
	assert.True(t, result.nCached == 2)
	assert.True(t, result.latency == 111)
}
