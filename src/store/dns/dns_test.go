package dns_store

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func queryDns(msg *dns.Msg) (*dns.Msg, error) {
	dnsClient := &dns.Client{}
	dnsClient.Net = "udp"
	response, _, err := dnsClient.Exchange(msg, "127.1.0.53:53")
	return response, err

}

func Test_Dns(t *testing.T) {
	d := New("127.1.0.53:53")
	defer d.Stop()

	time.Sleep(time.Millisecond * 50)

	d.StoreRecord("test", "127.0.0.1")

	msg := &dns.Msg{}
	msg.SetQuestion("test.internal.disembark.", dns.TypeA)

	resp, err := queryDns(msg)
	assert.ErrorIs(t, err, nil, "dns query is successful")

	assert.Equal(t, "test.internal.disembark.\t3600\tIN\tA\t127.0.0.1", resp.Answer[0].String(), "DNS record is valid")

	msg = &dns.Msg{}
	msg.SetQuestion("google.com.", dns.TypeA)

	resp, err = queryDns(msg)
	assert.ErrorIs(t, err, nil, "dns query is successful")

	assert.Equal(t, dns.RcodeServerFailure, resp.Rcode, "we didnt proxy the request")

	d.SetProxy("1.1.1.1:53")

	resp, err = queryDns(msg)
	assert.ErrorIs(t, err, nil, "dns query is successful")

	assert.Equal(t, dns.RcodeSuccess, resp.Rcode, "we did proxy the request")

	msg.SetQuestion("1.0.0.127.in-addr.arpa.", dns.TypePTR)

	resp, err = queryDns(msg)
	assert.ErrorIs(t, err, nil, "dns query is successful")

	assert.Equal(t, "1.0.0.127.in-addr.arpa.\t3600\tIN\tPTR\ttest.internal.disembark.", resp.Answer[0].String(), "DNS record is valid")
}
