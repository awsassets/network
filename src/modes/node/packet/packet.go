package packet

import (
	"net"
)

type PacketType byte

const (
	PacketTypeData PacketType = iota
	PacketTypePing
	PacketTypePong
	PacketTypePongAesPresent
	PacketTypeExchange
	PacketTypeExchangeResponse
)

const MTU = 1400

/*
# Data Packet

0              0              1              2              3
1             1              ip start 4 bytes ...

2           ip end...        payload n bytes....


# Ping Packet

0              0              1              2              3
1             1              ip start 4 bytes ...

2           ip end...        uuid start 16 bytes ...

3

4

5

6         uuid end...


# Pong Packet

0              0              1              2              3
1              2              uuid start 16 bytes ...

2

3

4

5         uuid end...


# PongAES Packet

0              0              1              2              3
1              3              uuid start 16 bytes ...

2

3

4

5         uuid end...        time start aes encrypted 16 bytes...

6

7                       time end...


# Exchange Packet

0              0              1              2              3
1             4              ip start 4 bytes ...

2          ip end...        uuid start 16 bytes ...

3

4

5

6         uuid end...       aes key encrypted n bytes...

# ExchangeResponse Packet

0              0              1              2              3
1             4              uuid start 16 bytes ...

2

3

4

5         uuid end...

*/

func WrapIpPkt(arr []byte, t PacketType, id []byte, ip net.IP) []byte {
	arr[0] = byte(t)
	copy(arr[1:5], ip.To4())
	copy(arr[5:], id)
	return arr[:5+len(id)]
}

func WrapPkt(arr []byte, t PacketType, id []byte) []byte {
	arr[0] = byte(t)
	copy(arr[1:], id)
	return arr[:1+len(id)]
}

func WrapData(arr []byte, ip net.IP, data []byte) []byte {
	arr[0] = byte(PacketTypeData)
	copy(arr[1:5], ip.To4())
	copy(arr[5:], data)
	return arr[:5+len(data)]
}
