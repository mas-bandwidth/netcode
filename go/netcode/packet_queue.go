package netcode

type PacketQueue struct {
	NumPackets int
	StartIndex int
	Packets    []Packet
}

func NewPacketQueue() *PacketQueue {
	q := &PacketQueue{}
	q.Packets = make([]Packet, PACKET_QUEUE_SIZE)
	return q
}

func (q *PacketQueue) Clear() {
	q.NumPackets = 0
	q.StartIndex = 0
	q.Packets = make([]Packet, PACKET_QUEUE_SIZE)
}

func (q *PacketQueue) Push(packet Packet) int {
	if q.NumPackets == PACKET_QUEUE_SIZE {
		return 0
	}

	index := (q.StartIndex + q.NumPackets) % PACKET_QUEUE_SIZE
	q.Packets[index] = packet
	q.NumPackets++
	return 1
}

func (q *PacketQueue) Pop() Packet {
	if q.NumPackets == 0 {
		return nil
	}

	packet := q.Packets[q.StartIndex]
	q.StartIndex = (q.StartIndex + 1) % PACKET_QUEUE_SIZE
	q.NumPackets--
	return packet
}
