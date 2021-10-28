package netutil

import (
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
)

func GetAddr(b []byte) (srcAddr string, dstAddr string, isTcp bool) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Info("failed to get addr: ", err)
			srcAddr = ""
			dstAddr = ""
		}
	}()
	if waterutil.IPv4Protocol(b) == waterutil.TCP || waterutil.IPv4Protocol(b) == waterutil.UDP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		srcPort := waterutil.IPv4SourcePort(b)
		dstPort := waterutil.IPv4DestinationPort(b)
		src := strings.Join([]string{srcIp.To4().String(), strconv.FormatUint(uint64(srcPort), 10)}, ":")
		dst := strings.Join([]string{dstIp.To4().String(), strconv.FormatUint(uint64(dstPort), 10)}, ":")
		//logrus.Printf("%s->%v", src, dst)
		return src, dst, waterutil.IPv4Protocol(b) == waterutil.TCP
	} else if waterutil.IPv4Protocol(b) == waterutil.ICMP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		return srcIp.To4().String(), dstIp.To4().String(), false
	}
	return "", "", false
}

func RemovePort(addr string) string {
	idx := strings.IndexRune(addr, ':')
	if idx == -1 {
		return addr
	}

	return addr[:idx]
}
