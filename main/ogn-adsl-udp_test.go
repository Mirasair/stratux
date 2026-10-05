package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestOgnMessageAcceptsNumericOnGround(t *testing.T) {
	var message OgnMessage
	if err := json.Unmarshal([]byte(`{"on_ground":1}`), &message); err != nil {
		t.Fatalf("numeric OGN on_ground must remain compatible: %v", err)
	}
	if message.On_ground != 1 {
		t.Fatalf("decoded OGN on_ground = %d, want 1", message.On_ground)
	}
}

func TestInternetTrafficModesAreMutuallyExclusive(t *testing.T) {
	oldSettings := globalSettings
	defer func() { globalSettings = oldSettings }()

	for _, test := range []struct {
		mode string
		tcp  bool
		udp  bool
	}{
		{internetTrafficModeNone, false, false},
		{internetTrafficModeAPRSTCP, true, false},
		{internetTrafficModeADSLUDP, false, true},
	} {
		if !setInternetTrafficMode(test.mode) {
			t.Fatalf("valid mode %q was rejected", test.mode)
		}
		if globalSettings.APRS_Enabled != test.tcp || globalSettings.APRS_UDP_Enabled != test.udp {
			t.Fatalf("mode %q produced TCP=%t UDP=%t, want TCP=%t UDP=%t", test.mode,
				globalSettings.APRS_Enabled, globalSettings.APRS_UDP_Enabled, test.tcp, test.udp)
		}
	}

	if setInternetTrafficMode("invalid") {
		t.Fatal("invalid internet traffic mode was accepted")
	}
	globalSettings.APRS_Enabled = true
	globalSettings.APRS_UDP_Enabled = true
	normalizeInternetTrafficSettings()
	if globalSettings.APRS_Enabled || !globalSettings.APRS_UDP_Enabled {
		t.Fatal("conflicting persisted settings were not normalized to UDP only")
	}
}

func TestAPRSUDPEndpoint(t *testing.T) {
	if got := aprsUDPEndpoint(); got != "ogn3.glidernet.org:14590" {
		t.Fatalf("unexpected endpoint %q", got)
	}
}

func unframeGDL90ForTest(message []byte) ([]byte, error) {
	end := len(message)
	for end > 0 && (message[end-1] == '\r' || message[end-1] == '\n') {
		end--
	}
	if end < 2 || message[0] != 0x7e || message[end-1] != 0x7e {
		return nil, errors.New("invalid GDL90 delimiters")
	}
	return unescapeGDL90Frame(message[1 : end-1])
}

func TestParsePADSLAndFrameTrackerMessage(t *testing.T) {
	const sentence = "$PADSL,008033BF6EA67D1A06880EC5D54709C96FF40E56E5*6D\r\n"
	wantPacket := []byte{
		0x00, 0x80, 0x33, 0xbf, 0x6e, 0xa6, 0x7d, 0x1a, 0x06, 0x88, 0x0e,
		0xc5, 0xd5, 0x47, 0x09, 0xc9, 0x6f, 0xf4, 0x0e, 0x56, 0xe5,
	}

	valid, ok := validateNMEAChecksum(sentence)
	if !ok {
		t.Fatal("captured $PADSL sentence did not pass its NMEA checksum")
	}
	packet, err := parsePADSLFields(strings.Split(valid, ","))
	if err != nil {
		t.Fatalf("parse $PADSL: %v", err)
	}
	if !bytes.Equal(packet, wantPacket) {
		t.Fatalf("parsed ADS-L packet:\n got %x\nwant %x", packet, wantPacket)
	}

	crcInit()
	message, err := makeAPRSUDPTrackerMessage(packet)
	if err != nil {
		t.Fatalf("frame tracker message: %v", err)
	}
	unescaped, err := unframeGDL90ForTest(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(unescaped) != 1+adslNetworkPacketBytes+2 || unescaped[0] != adslGDL90MessageID {
		t.Fatalf("unexpected unescaped GDL90 frame: %x", unescaped)
	}
	if !bytes.Equal(unescaped[1:1+adslNetworkPacketBytes], wantPacket) {
		t.Fatal("GDL90 framing changed the tracker ADS-L packet")
	}
}

func TestParsePADSLRejectsMalformedPayload(t *testing.T) {
	for _, fields := range [][]string{
		{"PADSL"},
		{"PADSL", "00"},
		{"PADSL", "008033BF6EA67D1A06880EC5D54709C96FF40E56EZ"},
		{"OTHER", "008033BF6EA67D1A06880EC5D54709C96FF40E56E5"},
	} {
		if _, err := parsePADSLFields(fields); err == nil {
			t.Fatalf("malformed fields accepted: %#v", fields)
		}
	}
}

func TestDecodeCapturedServerDatagram(t *testing.T) {
	// Real datagram returned by ogn3.glidernet.org. It contains seven complete
	// GDL90 0x60 frames, including duplicates and byte stuffing.
	const captured = "7e606002078c3a018820d3244711f00e007c020000007f01ef7e" +
		"7e60600207c9c4298c215b4c4703df0e0025428084007f084a7e" +
		"7e60600245cc30139422e9395be165f087d0c1c37c0000e3a37e" +
		"7e606002078c3a018820d3244711f00e007c020000007f01ef7e" +
		"7e60600207c9c42990215b4c4703df0e0026028084007f3ad47e" +
		"7e60600245cc30139422ec395be465f087d101c57c0000b6987e" +
		"7e606002408c4c0e9421bc934095ad041f230880ed005e908f7e0a"
	datagram, err := hex.DecodeString(captured)
	if err != nil {
		t.Fatal(err)
	}
	crcInit()
	packets, rejected := extractAPRSUDPADSLPackets(datagram)
	if rejected != 0 || len(packets) != 7 {
		t.Fatalf("extracted %d frames and rejected %d, want 7 and 0", len(packets), rejected)
	}

	reference := time.Date(2026, time.September, 15, 10, 0, 5, 500000000, time.UTC)
	decoded, err := decodeAPRSUDPADSLTraffic(packets[0], reference)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.message.Addr != "04EA30" || decoded.message.Addr_type != 3 {
		t.Fatalf("decoded identity = type %d address %s", decoded.message.Addr_type, decoded.message.Addr)
	}
	if decoded.message.Sys != "OGN" {
		t.Fatalf("decoded source = %q, want OGN", decoded.message.Sys)
	}
	if math.Abs(float64(decoded.message.Lat_deg)-50.023421) > 0.000002 ||
		math.Abs(float64(decoded.message.Lon_deg)-21.006394) > 0.000002 {
		t.Fatalf("decoded position = %.6f, %.6f", decoded.message.Lat_deg, decoded.message.Lon_deg)
	}
	if decoded.message.Timestamp != time.Date(2026, time.September, 15, 10, 0, 2, 0, time.UTC) {
		t.Fatalf("decoded timestamp = %s", decoded.message.Timestamp)
	}
	if decoded.message.Alt_hae_m != 316 || decoded.message.Speed_mps != 0 {
		t.Fatalf("decoded motion = alt %.0f m, speed %.2f m/s", decoded.message.Alt_hae_m, decoded.message.Speed_mps)
	}

	duplicate, err := decodeAPRSUDPADSLTraffic(packets[3], reference)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.data != duplicate.data {
		t.Fatal("captured duplicate did not decode to identical ADS-L data")
	}
}

func TestReconstructADSLTimestampBounds(t *testing.T) {
	reference := time.Date(2026, time.September, 15, 10, 0, 14, 0, time.UTC)
	if _, err := reconstructADSLTimestamp(12, reference); err == nil {
		t.Fatal("11-second-old ADS-L timestamp must be rejected")
	}
	reference = time.Date(2026, time.September, 15, 10, 0, 0, 0, time.UTC)
	if _, err := reconstructADSLTimestamp(12, reference); err == nil {
		t.Fatal("3-second-future ADS-L timestamp must be rejected")
	}
}

func TestExtractAPRSUDPADSLRejectsBadCRC(t *testing.T) {
	crcInit()
	message, err := makeAPRSUDPTrackerMessage(make([]byte, adslNetworkPacketBytes))
	if err != nil {
		t.Fatal(err)
	}
	message[2] ^= 0x01
	packets, rejected := extractAPRSUDPADSLPackets(message)
	if len(packets) != 0 || rejected != 1 {
		t.Fatalf("bad CRC result: %d packets, %d rejected", len(packets), rejected)
	}
}
