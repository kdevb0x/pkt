package main // import "github.com/kidoda/pkt"

import (
	"log"
	"net"
	"time"

	gp "github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/raw"
)

var (
	ethiface                  = "enp2s0"
	promiscious               = true
	snapshotLen int32         = 65535
	timeout     time.Duration = -1 * time.Second
)

func GetRawPacket(device string, promisc bool) ([]byte, error) {
	if promisc != false {
		promisc = promiscious
	}
	ifi, err := net.InterfaceByName(ethiface)
	if err != nil {
		log.Printf("Failed to open interface %s, INFO: %s", device, err)
		return nil, err
	}
	var config raw.Config
	conn, err := raw.ListenPacket(ifi, 0xccc, &config)
	if err != nil {
		log.Printf("Failure while listening for packet on interface %s, INFO: %s", device, err)
		return nil, err
	}
	defer conn.Close()

	conn.SetPromiscuous(promisc)
	conn.SetReadDeadline(<-time.After(timeout))

	buff := make([]byte, ifi.MTU)
	var frame ethernet.Frame

	for {
		n, addr, err := conn.ReadFrom(buff)
		if err != nil {
			log.Printf("Error buffering incomming packets: %s", err)
			return nil, err
		}
		if err := (&frame).UnmarshalBinary(buff[:n]); err != nil {
			log.Printf("Failed to unmarshal ethernet frame: %s", err)
			return nil, err
		}
		return frame.Payload, nil
	}
}

// Packet with some helper methods for analyzing .
type Packet interface {
	gp.Packet
}
