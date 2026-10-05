# ADS-L Exchange over UDP

Stratux can exchange ADS-L position reports with the OGN internet service over a connected
UDP socket. Select **ADS-L exchange (UDP)** under **Internet traffic** on the Settings page.
This mode and the legacy **OGN APRS (TCP)** mode are mutually exclusive.

The endpoint is fixed at `ogn3.glidernet.org:14590`. Stratux sends its own current ADS-L
position on this socket and receives nearby traffic on the same socket. The server only knows
where to return traffic after it has received a current ownship position, so reception requires
working GNSS data and a compatible tracker position report.

## Tracker input

To keep the internet report identical to the report prepared for radio transmission, Stratux
does not rebuild ADS-L from its internal GPS state. A compatible serial tracker must export the
prepared packet as:

```text
$PADSL,<42 hexadecimal characters>*CS
```

The 21 bytes are the ADS-L network header followed by the 20-byte prepared ADS-L payload. The
ADS-L CRC-24 is omitted. `CS` is the normal NMEA XOR checksum. Stratux verifies the sentence and
forwards the complete packet without changing its position, timestamp, track, speed or climb.

## UDP framing

Each tracker packet is wrapped in an experimental GDL90 message:

- message ID: `0x60`;
- payload: the 21 ADS-L bytes from `$PADSL`, without the ADS-L CRC-24;
- standard GDL90 CRC and byte stuffing;
- one line-feed byte (`0x0A`) after the closing GDL90 flag.

A UDP datagram received from the server may contain one or more GDL90 `0x60` frames. Stratux
checks the GDL90 CRC, removes byte stuffing, decodes ADS-L traffic and rejects malformed,
unsupported, duplicate or stale reports. Received targets enter the normal Stratux traffic
pipeline and are then available to GDL90, FLARM/NMEA, serial and BLE clients.

The sender retains only the newest complete tracker report while the internet path is unavailable;
historical ownship positions are not queued for later transmission.

## Privacy and operational notes

Enabling this mode sends the same prepared ownship ADS-L position content to the configured OGN
server over the internet. This is an experimental situational-awareness input, not a certified
collision-avoidance service. Operation also depends on mobile internet coverage and the exchange
server being available.
