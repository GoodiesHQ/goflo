package packets

import "github.com/goodieshq/goflo/internal/protocol"

func createHeader(pktType protocol.FloType) protocol.Header {
	return protocol.Header{
		Magic:   [4]byte{'F', 'L', 'O', 0x00},
		Version: protocol.FloVersion1,
		Type:    pktType,
	}
}
