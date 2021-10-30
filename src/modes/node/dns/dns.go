package dns

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

type DNS struct {
	records *cache.CacheArray
	mtx     sync.Mutex
}

func New() *DNS {
	d := &DNS{
		records: cache.NewArray(time.Minute, time.Minute*30),
	}
	go d.start()
	return d
}

func fixHostname(hostname string) string {
	if strings.HasSuffix(hostname, ".") {
		return hostname + "disembark.internal."
	}

	return hostname + ".disembark.internal."
}
func prtHostname(ip string) string {
	ipb := net.ParseIP(ip).To4()

	for i := 0; i < len(ipb)/2; i++ {
		ipb[i], ipb[len(ipb)-i-1] = ipb[len(ipb)-i-1], ipb[i]
	}

	return ipb.String() + ".in-addr.arpa."
}

func (d *DNS) StoreRecord(hostname, ip string) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.records.Store(fixHostname(hostname), ip, ip)
	d.records.Store(prtHostname(ip), fixHostname(hostname), fixHostname(hostname))
}

func (d *DNS) DeleteRecord(hostname string, ip string) {
	d.mtx.Lock()
	defer d.mtx.Unlock()

	d.records.Delete(fixHostname(hostname), ip)
	d.records.Delete(prtHostname(ip), fixHostname(hostname))
}

func (d *DNS) start() {
	udpServer := &dns.Server{Addr: "10.10.0.0:53", Net: "udp"}
	tcpServer := &dns.Server{Addr: "10.10.0.0:53", Net: "tcp"}

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

func (d *DNS) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := &dns.Msg{}
	m.SetReply(r)
	m.Compress = false

	answer := false
	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range m.Question {
			switch q.Qtype {
			case dns.TypeA:
				if v, ok := d.records.GetFirst(q.Name); ok {
					rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, v.(string)))
					if err == nil {
						m.Answer = append(m.Answer, rr)
						answer = true
					} else {
						logrus.Error("dns error: ", err)
						dns.HandleFailed(w, r)
						return
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
						dns.HandleFailed(w, r)
						return
					}
				}
			}
		}
	}

	if !answer {
		m := &dns.Msg{}
		m.SetRcode(r, dns.RcodeServerFailure)
		w.WriteMsg(m)
	} else {
		w.WriteMsg(m)
	}
}
