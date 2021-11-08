package netutil

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/songgao/water/waterutil"
)

func GetAddr(b []byte) (srcAddr string, dstAddr string, proto waterutil.IPProtocol) {
	defer func() {
		if err := recover(); err != nil {
			logrus.Debug("failed to get addr: ", err)
			srcAddr = ""
			dstAddr = ""
		}
	}()
	if len(b) == 0 || !waterutil.IsIPv4(b) {
		return "", "", 0
	}

	if waterutil.IPv4Protocol(b) == waterutil.TCP || waterutil.IPv4Protocol(b) == waterutil.UDP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		srcPort := waterutil.IPv4SourcePort(b)
		dstPort := waterutil.IPv4DestinationPort(b)
		src := fmt.Sprint(srcIp.To4().String(), ":", strconv.FormatUint(uint64(srcPort), 10))
		dst := fmt.Sprint(dstIp.To4().String(), ":", strconv.FormatUint(uint64(dstPort), 10))
		return src, dst, waterutil.IPv4Protocol(b)
	} else if waterutil.IPv4Protocol(b) == waterutil.ICMP {
		srcIp := waterutil.IPv4Source(b)
		dstIp := waterutil.IPv4Destination(b)
		return srcIp.To4().String(), dstIp.To4().String(), waterutil.IPv4Protocol(b)
	}
	return "", "", 0
}

func RemovePort(addr string) string {
	idx := strings.IndexRune(addr, ':')
	if idx == -1 {
		return addr
	}

	return addr[:idx]
}
