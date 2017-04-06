package netcode

const PACKET_QUEUE_SIZE = 256

type Queue struct {
	NumPackets int
	StartIndex int
	Packets []Packet
}

func NewQueue() *Queue {
	q := &Queue{}
	q.Packets = make([]Packet, PACKET_QUEUE_SIZE)
	return q
}

func (q *Queue) Clear() {
	q.NumPackets = 0
	q.StartIndex = 0
	q.Packets = make([]Packet, PACKET_QUEUE_SIZE)
}

func (q *Queue) Push(packet Packet) int {
	if q.NumPackets == PACKET_QUEUE_SIZE {
		return 0
	}

	index := (q.StartIndex + q.NumPackets) % PACKET_QUEUE_SIZE
	q.Packets[index] = packet
	q.NumPackets++
	return 1
}

func (q *Queue) Pop() Packet {
	if q.NumPackets == 0 {
		return nil
	}

	packet := q.Packets[q.StartIndex]
	q.StartIndex = ( q.StartIndex + 1 ) % PACKET_QUEUE_SIZE
	q.NumPackets--
	return packet
}

