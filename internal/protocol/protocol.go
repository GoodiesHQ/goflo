package protocol

// 4-byte magic constant at the start of each packet
const MAGIC = "FLO\x00"

type Packet interface {
	Marshal() ([]byte, error)
}

// FLO Protocol version
type FloVersion uint8

const (
	FloVersion1 FloVersion = 1
)

// Packet type
type FloType uint8

// Common header for all packets
type Header struct {
	Magic   [4]byte    // "FLO\xff" Magic bytes
	Version FloVersion // FLO Protocol version
	Type    FloType    // Packet type
}

// Direction of data flow
type FloDir uint8

const (
	DirectionBidi     FloDir = 0 // Client and Server Send and Receive
	DirectionUpload   FloDir = 1 // Client Send, Server Receive
	DirectionDownload FloDir = 2 // Client Receive, Server Send
)

const HeaderSize = 6

// UnmarshalHeader parses raw bytes into a Header struct
func UnmarshalHeader(data []byte) (*Header, error) {
	if len(data) < HeaderSize {
		return nil, ErrInvalidPacketSize
	}

	var header Header
	copy(header.Magic[:], data[0:4])

	if header.Magic != [4]byte{'F', 'L', 'O', 0x00} {
		return nil, ErrInvalidMagic
	}

	header.Version = FloVersion(data[4])
	header.Type = FloType(data[5])

	return &header, nil
}
