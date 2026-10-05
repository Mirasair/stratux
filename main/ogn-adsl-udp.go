/*
	Copyright (c) 2026
	Distributable under the terms of The "BSD New" License
	that can be found in the LICENSE file, herein included
	as part of this header.

	ogn-aprs-udp.go: ADS-L traffic exchange over UDP.
*/

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	aprsUDPDefaultHost          = "ogn3.glidernet.org"
	aprsUDPDefaultPort          = 14590
	aprsUDPSenderPollInterval   = 100 * time.Millisecond
	aprsUDPWriteTimeout         = 500 * time.Millisecond
	aprsUDPRetryInterval        = 3 * time.Second
	aprsUDPMaximumTrafficAge    = 10 * time.Second
	aprsUDPMaximumFutureTime    = 2 * time.Second
	aprsUDPDuplicateLifetime    = 10 * time.Second
	aprsUDPReadBufferBytes      = 65535
	aprsUDPMaxFramesPerDatagram = 256

	adslGDL90MessageID     = 0x60
	adslNetworkPacketBytes = 21 // Network header plus scrambled ADS-L Data, without ADS-L CRC-24.
	adslDataBytes          = 20 // ADS-L Header (5 bytes) plus Traffic payload (15 bytes).
	adslTrafficPayloadType = 0x02

	aprsUDPTrackerPacketQueueDepth = 8
)

var aprsUDPTrackerPacketChan = make(chan []byte, aprsUDPTrackerPacketQueueDepth)

type aprsUDPADSLTraffic struct {
	message OgnMessage
	data    [adslDataBytes]byte
}

// parsePADSLFields accepts the ADS-L network packet exported by a compatible
// tracker as $PADSL,<42 hexadecimal characters>*CS.
func parsePADSLFields(fields []string) ([]byte, error) {
	if len(fields) != 2 || fields[0] != "PADSL" {
		return nil, errors.New("invalid $PADSL field layout")
	}
	if len(fields[1]) != 2*adslNetworkPacketBytes {
		return nil, fmt.Errorf("$PADSL payload has %d hexadecimal characters, expected %d", len(fields[1]), 2*adslNetworkPacketBytes)
	}
	packet, err := hex.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("invalid $PADSL hexadecimal payload: %w", err)
	}
	return packet, nil
}

// queueAPRSUDPTrackerPacket deliberately retains only recent complete
// positions. Historical aircraft positions must not build up during a network
// outage.
func queueAPRSUDPTrackerPacket(packet []byte) {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case aprsUDPTrackerPacketChan <- copyOfPacket:
		return
	default:
	}

	select {
	case <-aprsUDPTrackerPacketChan:
	default:
	}
	select {
	case aprsUDPTrackerPacketChan <- copyOfPacket:
	default:
	}
}

// makeAPRSUDPTrackerMessage wraps the tracker-generated ADS-L packet in the
// experimental GDL90 message 0x60. The ADS-L CRC is omitted because GDL90 has
// its own CRC; LF terminates the UDP payload expected by the exchange server.
func makeAPRSUDPTrackerMessage(adslPacket []byte) ([]byte, error) {
	if len(adslPacket) != adslNetworkPacketBytes {
		return nil, fmt.Errorf("ADS-L network packet is %d bytes, expected %d", len(adslPacket), adslNetworkPacketBytes)
	}
	gdl90Data := make([]byte, 0, 1+len(adslPacket))
	gdl90Data = append(gdl90Data, adslGDL90MessageID)
	gdl90Data = append(gdl90Data, adslPacket...)
	message := prepareMessage(gdl90Data)
	return append(message, '\n'), nil
}

func aprsUDPEndpoint() string {
	return net.JoinHostPort(aprsUDPDefaultHost, strconv.Itoa(aprsUDPDefaultPort))
}

func xxteaDescrambleKey0(data []byte) {
	words := make([]uint32, len(data)/4)
	for index := range words {
		offset := 4 * index
		words[index] = uint32(data[offset]) |
			uint32(data[offset+1])<<8 |
			uint32(data[offset+2])<<16 |
			uint32(data[offset+3])<<24
	}

	const delta uint32 = 0x9e3779b9
	var sum uint32
	for round := 0; round < 6; round++ {
		sum += delta
	}
	y := words[0]
	for round := 0; round < 6; round++ {
		for index := len(words) - 1; index > 0; index-- {
			z := words[index-1]
			words[index] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + z)
			y = words[index]
		}
		z := words[len(words)-1]
		words[0] -= (((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^ ((sum ^ y) + z)
		y = words[0]
		sum -= delta
	}

	for index, word := range words {
		offset := 4 * index
		data[offset] = byte(word)
		data[offset+1] = byte(word >> 8)
		data[offset+2] = byte(word >> 16)
		data[offset+3] = byte(word >> 24)
	}
}

func readLittleEndianBits(src []byte, bitOffset, bitWidth uint) uint64 {
	var value uint64
	for bit := uint(0); bit < bitWidth; bit++ {
		if src[(bitOffset+bit)/8]&(1<<((bitOffset+bit)%8)) != 0 {
			value |= uint64(1) << bit
		}
	}
	return value
}

func signedBits(value uint64, width uint) int64 {
	if value&(uint64(1)<<(width-1)) != 0 {
		value |= ^uint64(0) << width
	}
	return int64(value)
}

func decodeUnsignedVR(value uint64, baseBits uint) uint64 {
	threshold := uint64(1) << baseBits
	valueRange := value >> baseBits
	value &= threshold - 1
	switch valueRange {
	case 0:
		return value
	case 1:
		return threshold + 1 + (value << 1)
	case 2:
		return 3*threshold + 2 + (value << 2)
	default:
		return 7*threshold + 4 + (value << 3)
	}
}

func decodeSignedVR(value uint64, baseBits uint) int64 {
	signMask := uint64(1) << (baseBits + 2)
	magnitude := int64(decodeUnsignedVR(value&(signMask-1), baseBits))
	if value&signMask != 0 {
		return -magnitude
	}
	return magnitude
}

func unescapeGDL90Frame(frame []byte) ([]byte, error) {
	clear := make([]byte, 0, len(frame))
	for index := 0; index < len(frame); index++ {
		value := frame[index]
		if value == 0x7d {
			index++
			if index >= len(frame) {
				return nil, errors.New("truncated GDL90 escape")
			}
			value = frame[index] ^ 0x20
		}
		clear = append(clear, value)
	}
	return clear, nil
}

// extractAPRSUDPADSLPackets separates all complete GDL90/0x60 frames in one
// UDP datagram. A datagram may contain several frames and may end in LF/CRLF.
func extractAPRSUDPADSLPackets(datagram []byte) (packets [][]byte, rejected int) {
	frameStart := -1
	for index, value := range datagram {
		if value != 0x7e {
			continue
		}
		if frameStart >= 0 && index > frameStart+1 {
			if len(packets) >= aprsUDPMaxFramesPerDatagram {
				rejected++
				frameStart = index
				continue
			}
			frame, err := unescapeGDL90Frame(datagram[frameStart+1 : index])
			if err != nil || len(frame) != 1+adslNetworkPacketBytes+2 || frame[0] != adslGDL90MessageID {
				rejected++
				frameStart = index
				continue
			}
			crcOffset := len(frame) - 2
			gotCRC := uint16(frame[crcOffset]) | uint16(frame[crcOffset+1])<<8
			if crcCompute(frame[:crcOffset]) != gotCRC {
				rejected++
				frameStart = index
				continue
			}
			packets = append(packets, append([]byte(nil), frame[1:crcOffset]...))
		}
		frameStart = index
	}
	return packets, rejected
}

func reconstructADSLTimestamp(quarterSeconds uint64, reference time.Time) (time.Time, error) {
	if quarterSeconds >= 60 {
		return time.Time{}, errors.New("ADS-L timestamp is unavailable")
	}
	reference = reference.UTC()
	stamp := reference.Truncate(15 * time.Second).Add(time.Duration(quarterSeconds) * 250 * time.Millisecond)
	delta := stamp.Sub(reference)
	if delta > 3*time.Second {
		stamp = stamp.Add(-15 * time.Second)
	} else if delta <= -12*time.Second {
		stamp = stamp.Add(15 * time.Second)
	}
	age := reference.Sub(stamp)
	if age > aprsUDPMaximumTrafficAge {
		return time.Time{}, fmt.Errorf("ADS-L traffic is %.3f seconds old", age.Seconds())
	}
	if age < -aprsUDPMaximumFutureTime {
		return time.Time{}, fmt.Errorf("ADS-L traffic timestamp is %.3f seconds in the future", -age.Seconds())
	}
	return stamp, nil
}

func adslAircraftCategoryToOGN(category uint64) string {
	ognCategory := [...]uint8{
		0, 8, 9, 3, 1, 12, 2, 7,
		4, 13, 3, 13, 13, 13, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	if category >= uint64(len(ognCategory)) {
		return "0"
	}
	return strings.ToUpper(strconv.FormatUint(uint64(ognCategory[category]), 16))
}

func adslAddressTypeToOGN(mappingTable uint64) int32 {
	switch mappingTable {
	case 5:
		return 1 // ICAO.
	case 6, 8:
		return 2 // FLARM or FANET.
	case 7:
		return 3 // OGN Tracker.
	default:
		return 0 // Random, privacy, manufacturer or unknown mapping.
	}
}

func adslAddressSystem(mappingTable uint64) string {
	switch mappingTable {
	case 0, 1, 2, 3, 4:
		return "RND"
	case 5:
		return "ICA"
	case 6:
		return "FLR"
	case 7:
		return "OGN"
	case 8:
		return "FNT"
	default:
		return "ADSL"
	}
}

func decodeAPRSUDPADSLTraffic(packet []byte, reference time.Time) (aprsUDPADSLTraffic, error) {
	if len(packet) != adslNetworkPacketBytes {
		return aprsUDPADSLTraffic{}, fmt.Errorf("ADS-L network packet is %d bytes, expected %d", len(packet), adslNetworkPacketBytes)
	}
	networkHeader := packet[0]
	if networkHeader&0x0f > 1 {
		return aprsUDPADSLTraffic{}, fmt.Errorf("unsupported ADS-L protocol version %d", networkHeader&0x0f)
	}
	if networkHeader&0x10 != 0 {
		return aprsUDPADSLTraffic{}, errors.New("signed ADS-L network packet has no signature in UDP payload")
	}

	var decoded aprsUDPADSLTraffic
	copy(decoded.data[:], packet[1:])
	switch (networkHeader >> 5) & 0x03 {
	case 0:
		xxteaDescrambleKey0(decoded.data[:])
	case 3:
		// Scrambling disabled by the sender.
	default:
		return aprsUDPADSLTraffic{}, fmt.Errorf("unsupported ADS-L key index %d", (networkHeader>>5)&0x03)
	}

	if readLittleEndianBits(decoded.data[:], 0, 8)&0x7f != adslTrafficPayloadType {
		return aprsUDPADSLTraffic{}, fmt.Errorf("unsupported ADS-L payload type 0x%02x", readLittleEndianBits(decoded.data[:], 0, 8))
	}

	addressWord := readLittleEndianBits(decoded.data[:], 8, 32)
	mappingTable := addressWord & 0x3f
	address := (addressWord >> 6) & 0xffffff
	stamp, err := reconstructADSLTimestamp(readLittleEndianBits(decoded.data[:], 40, 6), reference)
	if err != nil {
		return aprsUDPADSLTraffic{}, err
	}

	speedWord := readLittleEndianBits(decoded.data[:], 104, 8)
	if speedWord == 0xff {
		return aprsUDPADSLTraffic{}, errors.New("ADS-L ground speed is unavailable")
	}
	altitudeWord := readLittleEndianBits(decoded.data[:], 112, 14)
	if altitudeWord == 0x3fff {
		return aprsUDPADSLTraffic{}, errors.New("ADS-L altitude is unavailable")
	}
	climbWord := readLittleEndianBits(decoded.data[:], 126, 9)
	climbMPS := 0.0
	if climbWord != 0x1ff {
		climbMPS = float64(decodeSignedVR(climbWord, 6)) * 0.125
	}

	onGround := int32(0)
	if readLittleEndianBits(decoded.data[:], 46, 2) == 1 {
		onGround = 1
	}
	emergency := readLittleEndianBits(decoded.data[:], 53, 3)
	priorityStatus := uint8(0)
	if emergency != 0 && emergency != 1 {
		priorityStatus = 1
	}
	navigationIntegrity := int(readLittleEndianBits(decoded.data[:], 148, 4))
	nic := 0
	if navigationIntegrity > 0 {
		nic = navigationIntegrity - 1
	}
	horizontalAccuracy := int(readLittleEndianBits(decoded.data[:], 152, 3))
	nacp := 0
	if horizontalAccuracy > 0 {
		nacp = horizontalAccuracy + 4
	}

	decoded.message = OgnMessage{
		Sys:             adslAddressSystem(mappingTable),
		Time:            float64(stamp.UnixNano()) / float64(time.Second),
		Timestamp:       stamp,
		Addr:            fmt.Sprintf("%06X", address),
		Addr_type:       adslAddressTypeToOGN(mappingTable),
		Acft_type:       adslAircraftCategoryToOGN(readLittleEndianBits(decoded.data[:], 48, 5)),
		Lat_deg:         float32(float64(signedBits(readLittleEndianBits(decoded.data[:], 56, 24), 24)) / 93206.0),
		Lon_deg:         float32(float64(signedBits(readLittleEndianBits(decoded.data[:], 80, 24), 24)) / 46603.0),
		Alt_hae_m:       float32(int64(decodeUnsignedVR(altitudeWord, 12)) - 320),
		Track_deg:       float64(readLittleEndianBits(decoded.data[:], 135, 9)) * 360.0 / 512.0,
		Speed_mps:       float64(decodeUnsignedVR(speedWord, 6)) * 0.25,
		Climb_mps:       climbMPS,
		On_ground:       onGround,
		NIC:             nic,
		NACp:            nacp,
		Priority_status: priorityStatus,
	}
	return decoded, nil
}

func aprsUDPReferenceTime(receivedAt time.Time) time.Time {
	mySituation.muGPS.Lock()
	defer mySituation.muGPS.Unlock()
	if !mySituation.GPSTime.IsZero() {
		fixAge := stratuxClock.Since(mySituation.GPSLastFixLocalTime)
		if fixAge >= 0 && fixAge <= 5*time.Second {
			return mySituation.GPSTime.Add(fixAge).UTC()
		}
	}
	return receivedAt.UTC()
}

func aprsUDPReceiver(conn net.Conn) error {
	buffer := make([]byte, aprsUDPReadBufferBytes)
	duplicates := make(map[[adslDataBytes]byte]time.Time)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return err
		}
		receivedAt := time.Now().UTC()
		globalStatus.APRS_UDP_MessagesReceived++
		globalStatus.APRS_UDP_BytesReceived += uint64(n)
		globalStatus.APRS_UDP_LastReceiveTime = receivedAt.Format(time.RFC3339Nano)

		packets, rejected := extractAPRSUDPADSLPackets(buffer[:n])
		globalStatus.APRS_UDP_TrafficRejected += uint64(rejected)
		reference := aprsUDPReferenceTime(receivedAt)
		for _, packet := range packets {
			decoded, err := decodeAPRSUDPADSLTraffic(packet, reference)
			if err != nil {
				globalStatus.APRS_UDP_TrafficRejected++
				continue
			}
			if lastSeen, ok := duplicates[decoded.data]; ok && receivedAt.Sub(lastSeen) <= aprsUDPDuplicateLifetime {
				globalStatus.APRS_UDP_TrafficDuplicates++
				continue
			}
			duplicates[decoded.data] = receivedAt
			for key, lastSeen := range duplicates {
				if receivedAt.Sub(lastSeen) > aprsUDPDuplicateLifetime {
					delete(duplicates, key)
				}
			}

			importOgnTrafficMessage(decoded.message, "ADS-L UDP "+decoded.message.Addr, false)
			globalStatus.APRS_UDP_TrafficDecoded++
		}
	}
}

func setAPRSUDPError(err error) {
	globalStatus.APRS_UDP_Active = false
	globalStatus.APRS_UDP_Errors++
	globalStatus.APRS_UDP_LastError = err.Error()
}

func aprsUDPSender() {
	ticker := time.NewTicker(aprsUDPSenderPollInterval)
	defer ticker.Stop()

	endpoint := aprsUDPEndpoint()
	var conn net.Conn
	var nextConnect time.Time
	var lastLoggedError string
	var pendingADSLPacket []byte
	var receiverDone <-chan error

	closeConnection := func() {
		if conn != nil {
			conn.Close()
			conn = nil
		}
		receiverDone = nil
		globalStatus.APRS_UDP_Active = false
	}

	for now := range ticker.C {
	drainTrackerPackets:
		for {
			select {
			case packet := <-aprsUDPTrackerPacketChan:
				pendingADSLPacket = packet
			default:
				break drainTrackerPackets
			}
		}

		if !globalSettings.APRS_UDP_Enabled {
			closeConnection()
			nextConnect = time.Time{}
			lastLoggedError = ""
			pendingADSLPacket = nil
			globalStatus.APRS_UDP_LastError = ""
			continue
		}

		if conn != nil && receiverDone != nil {
			select {
			case readErr := <-receiverDone:
				setAPRSUDPError(readErr)
				if readErr.Error() != lastLoggedError {
					log.Printf("ADS-L UDP read from %s failed: %s\n", endpoint, readErr)
					lastLoggedError = readErr.Error()
				}
				closeConnection()
				nextConnect = now.Add(aprsUDPRetryInterval)
				continue
			default:
			}
		}

		if conn == nil {
			if now.Before(nextConnect) {
				pendingADSLPacket = nil
				continue
			}
			var err error
			conn, err = net.DialTimeout("udp", endpoint, aprsUDPWriteTimeout)
			if err != nil {
				setAPRSUDPError(err)
				nextConnect = now.Add(aprsUDPRetryInterval)
				if err.Error() != lastLoggedError {
					log.Printf("ADS-L UDP could not open %s: %s\n", endpoint, err)
					lastLoggedError = err.Error()
				}
				continue
			}
			globalStatus.APRS_UDP_Active = true
			globalStatus.APRS_UDP_LastError = ""
			lastLoggedError = ""
			done := make(chan error, 1)
			receiverDone = done
			go func(reader net.Conn, result chan<- error) {
				result <- aprsUDPReceiver(reader)
			}(conn, done)
			log.Printf("ADS-L UDP exchange active with %s\n", endpoint)
		}

		if pendingADSLPacket == nil {
			continue
		}

		payload, err := makeAPRSUDPTrackerMessage(pendingADSLPacket)
		pendingADSLPacket = nil
		if err != nil {
			setAPRSUDPError(err)
			if err.Error() != lastLoggedError {
				log.Printf("ADS-L UDP could not frame tracker position: %s\n", err)
				lastLoggedError = err.Error()
			}
			continue
		}

		conn.SetWriteDeadline(now.Add(aprsUDPWriteTimeout))
		n, err := conn.Write(payload)
		if err != nil {
			setAPRSUDPError(err)
			if err.Error() != lastLoggedError {
				log.Printf("ADS-L UDP write to %s failed: %s\n", endpoint, err)
				lastLoggedError = err.Error()
			}
			closeConnection()
			nextConnect = now.Add(aprsUDPRetryInterval)
			continue
		}

		globalStatus.APRS_UDP_Active = true
		globalStatus.APRS_UDP_MessagesSent++
		globalStatus.APRS_UDP_BytesSent += uint64(n)
		globalStatus.APRS_UDP_LastSendTime = now.UTC().Format(time.RFC3339Nano)
		globalStatus.APRS_UDP_LastError = ""
		lastLoggedError = ""
	}
}
