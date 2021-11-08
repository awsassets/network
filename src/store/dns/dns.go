package dns_store

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type DnsStore struct {
	records      cache.CacheArray
	mtx          sync.Mutex
	proxy        string
	doneCtx      context.Context
	cancel       context.CancelFunc
	stopResolved chan struct{}
}

type MockDnsStore struct {
	StopFunc         func()
	SetProxyFunc     func(proxy string)
	StoreRecordFunc  func(hostname, ip string)
	DeleteRecordFunc func(hostname string, ip string)
}

type Store interface {
	Stop()
	SetProxy(proxy string)
	StoreRecord(hostname, ip string)
	DeleteRecord(hostname string, ip string)
}

func (s MockDnsStore) Stop() {
	s.StopFunc()
}

func (s MockDnsStore) SetProxy(proxy string) {
	s.SetProxyFunc(proxy)
}

func (s MockDnsStore) StoreRecord(hostname, ip string) {
	s.StoreRecordFunc(hostname, ip)
}

func (s MockDnsStore) DeleteRecord(hostname string, ip string) {
	s.DeleteRecordFunc(hostname, ip)
}

func New(bind ...string) Store {
	ctx, cancel := context.WithCancel(context.Background())
	s := &DnsStore{
		records:      cache.NewArray(time.Minute, time.Minute*30),
		doneCtx:      ctx,
		cancel:       cancel,
		stopResolved: make(chan struct{}),
	}

	if len(bind) == 0 {
		go s.start("172.10.0.53:53")
	} else {
		go s.start(bind[0])
	}

	return s
}

func (s *DnsStore) Stop() {
	s.cancel()
	<-s.stopResolved
}

func (s *DnsStore) SetProxy(proxy string) {
	s.proxy = proxy
}

func (s *DnsStore) StoreRecord(hostname, ip string) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.records.Store(fixHostname(hostname), ip, ip)
	s.records.Store(prtHostname(ip), fixHostname(hostname), fixHostname(hostname))
}

func (s *DnsStore) DeleteRecord(hostname string, ip string) {
	s.mtx.Lock()
	defer s.mtx.Unlock()

	s.records.Delete(fixHostname(hostname), ip)
	s.records.Delete(prtHostname(ip), fixHostname(hostname))
}

func (s *DnsStore) start(bind string) {
	pl, err := net.ListenPacket("udp", bind)
	if err != nil {
		logrus.Fatal(err)
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil {
		logrus.Fatal(err)
	}

	go func() {
		if err := dns.ActivateAndServe(nil, pl, s); err != nil {
			if s.doneCtx.Err() == nil {
				logrus.Fatal(err)
			}
		}
	}()

	go func() {
		if err := dns.ActivateAndServe(ln, nil, s); err != nil {
			if s.doneCtx.Err() == nil {
				logrus.Fatal(err)
			}
		}
	}()

	<-s.doneCtx.Done()
	_ = pl.Close()
	_ = ln.Close()
	close(s.stopResolved)
}

func (s *DnsStore) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			answer := false
			switch q.Qtype {
			case dns.TypeA:
				if v, ok := s.records.GetFirst(q.Name); ok {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, v.(string)))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						answer = true
					} else {
						logrus.Error("dns error: ", err)
						continue
					}
				}
			case dns.TypePTR:
				if v, ok := s.records.GetFirst(q.Name); ok {
					rr, err := dns.NewRR(fmt.Sprintf("%s PTR %s", q.Name, v.(string)))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						answer = true
					} else {
						logrus.Error("dns error: ", err)
						continue
					}
				}
			}
			if !answer && s.proxy != "" {
				queryMsg := &dns.Msg{}
				r.CopyTo(queryMsg)

				queryMsg.Question = []dns.Question{q}

				msg, err := lookup(s.proxy, queryMsg)
				if err != nil {
					logrus.Error("dns error: ", err)
					continue
				}

				if len(msg.Answer) > 0 {
					m.Answer = append(m.Answer, msg.Answer[0])
				}
			}
		}
	}

	if len(m.Answer) == 0 {
		m := &dns.Msg{}
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	} else {
		_ = w.WriteMsg(m)
	}
}

func lookup(server string, m *dns.Msg) (*dns.Msg, error) {
	dnsClient := &dns.Client{}
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(m, server)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func fixHostname(hostname string) string {
	idx := strings.IndexRune(hostname, '.')

	if idx == len(hostname) || idx == -1 {
		hostname = hostname + ".internal.disembark."
	}

	if !strings.HasSuffix(hostname, ".") {
		return hostname + "."
	}

	return hostname
}

func prtHostname(ip string) string {
	ipb := net.ParseIP(ip).To4()

	for i := 0; i < len(ipb)/2; i++ {
		ipb[i], ipb[len(ipb)-i-1] = ipb[len(ipb)-i-1], ipb[i]
	}

	return ipb.String() + ".in-addr.arpa."
}
