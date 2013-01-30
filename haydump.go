package main

import (
	"flag"
	"github.com/miekg/pcap"
	"hash/fnv"
	"log"
	"time"
)

// Hash the incoming packet
// Find if session already saw
// If not, spawn a new goroutine and create a channel in charge of this session
// Send the packet to the channel
func PacketMunger(queue <-chan *pcap.Packet) {
	var sessions = map[uint64]chan *pcap.Packet{}
	var sigchild = make(chan uint64, 12)

	for {
		select {

		case pkt := <-queue:
			hash := HashPacket(pkt)
			if _, present := sessions[hash]; !present {
				sessions[hash] = make(chan *pcap.Packet, 512)
				go SessionHandler(hash, sessions[hash], sigchild)
				log.Printf("%#x Spawning session\n", hash)
			}
			sessions[hash] <- pkt

		case sessionid := <-sigchild:
			close(sessions[sessionid])
			delete(sessions, sessionid)
			log.Printf("%#x Killed\n", sessionid)
		}
	}
}

func SessionHandler(hash uint64, incoming <-chan *pcap.Packet, sigchild chan uint64) {
	pkt := <-incoming
	for _, layer := range pkt.Headers {
		if _, tcpOk := layer.(*pcap.Tcphdr); tcpOk {
			TcpSessionHandler(hash, incoming, sigchild)
			return

		}
	}

	// XXX: If no handler found
	for {
		_ = <-incoming
	}
}

func TcpSessionHandler(hash uint64, incoming <-chan *pcap.Packet, sigchild chan uint64) {
	timeout := time.After(15 * time.Minute)
	finSent := map[uint16]bool{}

	for {
		select {
		case pkt, ok := <-incoming:
			if !ok {
				log.Printf("%#x Channel closed!\n", hash)
				return
			}

			for _, layer := range pkt.Headers {
				if tcp, tcpOk := layer.(*pcap.Tcphdr); tcpOk {
					if (tcp.Flags & pcap.TCP_FIN) == pcap.TCP_FIN {
						finSent[tcp.SrcPort] = true
						if val, present := finSent[tcp.DestPort]; present && val {
							log.Printf("%#x Kill me now\n", hash)
							sigchild <- hash
						}
					}
				}
			}

		case <-timeout:
			sigchild <- hash // you can kill me dady!
		}

	}
}

func HashPacket(pkt *pcap.Packet) uint64 {
	pkt.Decode()
	hash := fnv.New64a()

	for _, layer := range pkt.Headers {
		if ip, ipOk := layer.(*pcap.Iphdr); ipOk {
			buf := []byte{0, 0, 0, 0, byte(ip.Protocol)}

			for i := uint(0); i < 4; i++ {
				buf[i] |= byte(ip.SrcIp[i] ^ ip.DestIp[i])
			}
			hash.Write(buf)
		}

		if tcp, tcpOk := layer.(*pcap.Tcphdr); tcpOk {
			xorval := tcp.SrcPort ^ tcp.DestPort
			buf := []byte{byte(xorval >> 16), byte(xorval & 0xf)}
			hash.Write(buf)
		}

		if udp, udpOk := layer.(*pcap.Tcphdr); udpOk {
			xorval := udp.SrcPort ^ udp.DestPort
			buf := []byte{byte(xorval >> 16), byte(xorval & 0xf)}
			hash.Write(buf)
		}

		if icmp, icmpOk := layer.(*pcap.Icmphdr); icmpOk {
			buf := []byte{byte(icmp.Id), byte(icmp.Seq)}
			hash.Write(buf)
		}
	}
	return hash.Sum64()
}

func main() {
	var device *string = flag.String("i", "eth0", "interface")
	var snaplen *int = flag.Int("s", 65535, "snaplen")

	flag.Parse()

	p, err := pcap.OpenLive(*device, int32(*snaplen), true, 1000)
	if err != nil {
		log.Fatal("Cannot open interface: ", err)
	}

	munger := make(chan *pcap.Packet, 4096)
	go PacketMunger(munger)

	for {
		frame := p.Next()
		if frame == nil {
			time.Sleep(100)
			continue
		} else {
			munger <- frame
		}
	}
}
