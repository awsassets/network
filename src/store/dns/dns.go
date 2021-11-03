package dns_store

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/disembark/network/src/cache"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type Store struct {
	records *cache.CacheArray
	mtx     sync.Mutex
	proxy   string
}

func New() *Store {
	d := &Store{
		records: cache.NewArray(time.Minute, time.Minute*30),
	}
	go d.start()
	return d
}

func (s *Store) SetProxy(proxy string) {
	s.proxy = proxy
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

func (d *Store) StoreRecord(hostname, ip string) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.records.Store(fixHostname(hostname), ip, ip)
	d.records.Store(prtHostname(ip), fixHostname(hostname), fixHostname(hostname))
}

func (d *Store) DeleteRecord(hostname string, ip string) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.records.Delete(fixHostname(hostname), ip)
	d.records.Delete(prtHostname(ip), fixHostname(hostname))
}

func (d *Store) start() {
	udpServer := &dns.Server{Addr: "172.10.0.53:53", Net: "udp"}
	tcpServer := &dns.Server{Addr: "172.10.0.53:53", Net: "tcp"}

	dns.HandleFunc(".", d.handleDnsRequest)

	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			logrus.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			logrus.Fatal(err)
		}
	}()
}

func (d *Store) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			answer := false
			switch q.Qtype {
			case dns.TypeA:
				if v, ok := d.records.GetFirst(q.Name); ok {
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
				if v, ok := d.records.GetFirst(q.Name); ok {
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
			if !answer && d.proxy != "" {
				queryMsg := &dns.Msg{}
				r.CopyTo(queryMsg)

				queryMsg.Question = []dns.Question{q}

				msg, err := lookup(d.proxy, queryMsg)
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
