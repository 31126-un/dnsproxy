package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	glcache "github.com/AdguardTeam/golibs/cache"
	"github.com/AdguardTeam/golibs/log"
	"github.com/miekg/dns"
	ping "github.com/sparrc/go-ping"
)

const cacheTTLSec = 10 * 60 // cache TTL in seconds

// FastestAddr - object data
type FastestAddr struct {
	cache glcache.Cache // cache of the fastest IP addresses
}

// Init - initialize module
func (f *FastestAddr) Init() {
	conf := glcache.Config{
		MaxSize:   1 * 1024 * 1024,
		EnableLRU: true,
	}
	f.cache = glcache.New(conf)
}

type cacheEntry struct {
	status int //0:ok; 1:timed out
}

/*
expire [4]byte
status byte
*/
func packCacheEntry(ent *cacheEntry) []byte {
	expire := uint32(time.Now().Unix()) + cacheTTLSec
	var d []byte
	d = make([]byte, 4+1)
	binary.BigEndian.PutUint32(d, expire)
	d[4] = byte(ent.status)
	return d
}

func unpackCacheEntry(data []byte) *cacheEntry {
	now := time.Now().Unix()
	expire := binary.BigEndian.Uint32(data[:4])
	if int64(expire) <= now {
		return nil
	}
	ent := cacheEntry{}
	ent.status = int(data[4])
	return &ent
}

// find in cache
func (f *FastestAddr) cacheFind(domain string, ip net.IP) int {
	val := f.cache.Get(ip)
	if val == nil {
		return -1
	}
	ent := unpackCacheEntry(val)
	if ent == nil {
		return -1
	}
	if ent.status != 0 {
		return ent.status
	}
	log.Debug("%s: Using %s address as the fastest (from cache)",
		domain, ip)
	return 0
}

// store in cache
func (f *FastestAddr) cacheAdd(addr net.IP, ok bool) {
	ip := addr.To4()
	if ip == nil {
		ip = addr
	}
	ent := cacheEntry{}
	ent.status = 0
	if !ok {
		ent.status = 1
	}
	val := packCacheEntry(&ent)
	f.cache.Set(ip, val)
}

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
			// if !strings.EqualFold(a.Header().Name, req.Question[0].Name) {
			// 	continue
			// }

			switch addr := a.(type) {
			case *dns.A:
				ip := addr.A.To4()
				status := p.fastestAddr.cacheFind(req.Question[0].Name, ip)
				if status == 0 {
					return prepareReply(r.Resp, ip), r.Upstream, nil
				}
				total++

			case *dns.AAAA:
				ip := addr.AAAA
				status := p.fastestAddr.cacheFind(req.Question[0].Name, ip)
				if status == 0 {
					return prepareReply(r.Resp, ip), r.Upstream, nil
				}
				total++
			}
		}
	}

	if total <= 1 {
		return replies[0].Resp, replies[0].Upstream, nil
	}

	ch := make(chan *pingResult, total)
	total = 0
	for _, r := range replies {
		for _, a := range r.Resp.Answer {
			// if !strings.EqualFold(a.Header().Name, req.Question[0].Name) {
			// 	continue
			// }

			switch addr := a.(type) {
			case *dns.A:
				ip := addr.A.To4()
				status := p.fastestAddr.cacheFind(req.Question[0].Name, ip)
				if status == -1 {
					go p.fastestAddr.pingDo(ip, &r, ch)
					total++
				}

			case *dns.AAAA:
				ip := addr.AAAA
				status := p.fastestAddr.cacheFind(req.Question[0].Name, ip)
				if status == -1 {
					go p.fastestAddr.pingDo(ip, &r, ch)
					total++
				}
			}
		}
	}

	if total == 0 {
		return replies[0].Resp, replies[0].Upstream, nil
	}

	reply, upstream, address, err := p.fastestAddr.pingWait(total, ch)
	if err != nil {
		return replies[0].Resp, replies[0].Upstream, nil
	}

	return prepareReply(reply, address), upstream, nil
}

// remove all A/AAAA records, leaving only the fastest one
func prepareReply(resp *dns.Msg, address net.IP) *dns.Msg {
	ans := []dns.RR{}
	for _, a := range resp.Answer {
		switch addr := a.(type) {
		case *dns.A:
			if address.To4().Equal(addr.A.To4()) {
				ans = append(ans, a)
			}

		case *dns.AAAA:
			if address.Equal(addr.AAAA) {
				ans = append(ans, a)
			}

		default:
			ans = append(ans, a)
		}
	}
	resp.Answer = ans
	return resp
}

type pingResult struct {
	addr  net.IP
	exres *upstream.ExchangeAllResult
	err   error
}

// Ping an address, send signal to the channel
func (f *FastestAddr) pingDo(addr net.IP, exres *upstream.ExchangeAllResult, ch chan *pingResult) {
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
		res.err = fmt.Errorf("%s: no reply from %s",
			res.exres.Resp.Question[0].Name, addr)
		log.Debug("%s", res.err)
	}
	ch <- res
}

// Wait for the first successful ping result
func (f *FastestAddr) pingWait(total int, ch chan *pingResult) (*dns.Msg, upstream.Upstream, net.IP, error) {
	n := 0
	for {
		select {
		case res := <-ch:
			n++
			if res.err != nil {
				f.cacheAdd(res.addr, false)
				break
			}

			log.Debug("%s: Using %s address as the fastest",
				res.exres.Resp.Question[0].Name, res.addr)

			f.cacheAdd(res.addr, true)

			return res.exres.Resp, res.exres.Upstream, res.addr, nil
		}

		if n == total {
			return nil, nil, nil, fmt.Errorf("ping didn't work")
		}
	}
}
