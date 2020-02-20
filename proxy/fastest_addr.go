package proxy

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	ping "github.com/sparrc/go-ping"
)

// Return DNS response containing the fastest IP address
// Algorithm:
// . Send requests to all upstream servers
// . Receive responses
// . For each response, for each IP address, send ICMP packet
// . Receive ICMP packets.  The first received packet makes it the fastest IP address.
// . Return DNS packet containing the chosen IP address (remove all other IP addresses from the packet)
func (p *Proxy) exchangeFastest(req *dns.Msg, upstreams []upstream.Upstream) (*dns.Msg, upstream.Upstream, error) {
	replies, err := upstream.ExchangeAll(upstreams, req)
	if err != nil || len(replies) == 0 {
		return nil, nil, err
	}

	total := 0
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			if strings.EqualFold(a.Header().Name, req.Question[0].Name) {
				continue
			}

			switch a.(type) {
			case *dns.A:
				total++

			case *dns.AAAA:
				total++
			}
		}
	}

	if total <= 1 {
		return replies[0].Resp, replies[0].Upstream, nil
	}

	ch := make(chan *pingResult, len(upstreams))
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			if strings.EqualFold(a.Header().Name, req.Question[0].Name) {
				continue
			}

			switch addr := a.(type) {
			case *dns.A:
				go pingDo(addr.A, &r, ch)

			case *dns.AAAA:
				go pingDo(addr.AAAA, &r, ch)
			}
		}
	}

	reply, upstream, err := pingWait(total, ch)
	if err != nil {
		return replies[0].Resp, replies[0].Upstream, nil
	}
	return reply, upstream, nil
}

type pingResult struct {
	addr  net.IP
	exres *upstream.ExchangeAllResult
	err   error
}

// Ping an address, send signal to the channel
func pingDo(addr net.IP, exres *upstream.ExchangeAllResult, ch chan *pingResult) {
	res := &pingResult{}
	res.addr = addr
	res.exres = exres
	pinger, err := ping.NewPinger(addr.String())
	if err != nil {
		log.Error("ping.NewPinger(): %v", err)
		res.err = err
		ch <- res
		return
	}

	pinger.SetPrivileged(true)
	pinger.Timeout = time.Duration(1000) * time.Millisecond
	pinger.Count = 1
	reply := false
	pinger.OnRecv = func(pkt *ping.Packet) {
		// log.Tracef("Received ICMP Reply from %v", target)
		reply = true
	}
	log.Debug("%s: Sending ICMP Echo to %s",
		res.exres.Resp.Question[0].Name, addr)
	pinger.Run()

	if !reply {
		res.err = fmt.Errorf("no reply from %s", addr)
	}
	ch <- res
}

// Wait for the first successful ping result, prepare response and return
func pingWait(total int, ch chan *pingResult) (*dns.Msg, upstream.Upstream, error) {
	n := 0
	for {
		select {
		case res := <-ch:
			n++
			if res.err != nil {
				break
			}

			log.Debug("%s: Using %s address as the fastest",
				res.exres.Resp.Question[0].Name, res.addr)

			resp := res.exres.Resp
			ans := []dns.RR{}
			// remove all A/AAAA records, leaving only the fastest one
			for _, a := range resp.Answer {
				switch addr := a.(type) {
				case *dns.A:
					if res.addr.To4().Equal(addr.A.To4()) {
						ans = append(ans, a)
					}

				case *dns.AAAA:
					if res.addr.Equal(addr.AAAA) {
						ans = append(ans, a)
					}

				default:
					ans = append(ans, a)
				}
			}
			resp.Answer = ans
			return resp, res.exres.Upstream, nil
		}

		if n == total {
			return nil, nil, fmt.Errorf("ping didn't work")
		}
	}
}
