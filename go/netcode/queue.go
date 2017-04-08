package netcode

import (
	"sync"
)

const PACKET_QUEUE_SIZE = 256

type Queue struct {
	NumPackets  int
	StartIndex  int
	packetMutex *sync.RWMutex
	Packets     map[int][]byte
}

func NewQueue() *Queue {
	q := &Queue{}
	q.packetMutex = &sync.RWMutex{}
	q.Packets = make(map[int][]byte)
	return q
}

func (q *Queue) Clear() {
	q.packetMutex.Lock()
	q.NumPackets = 0
	q.StartIndex = 0
	q.Packets = make(map[int][]byte)
	q.packetMutex.Unlock()
}

func (q *Queue) Push(packet []byte) int {
	q.packetMutex.Lock()
	defer q.packetMutex.Unlock()

	if q.NumPackets == PACKET_QUEUE_SIZE {
		return 0
	}

	index := (q.StartIndex + q.NumPackets) % PACKET_QUEUE_SIZE
	q.Packets[index] = packet
	q.NumPackets++
	return 1
}

func (q *Queue) Pop() []byte {
	q.packetMutex.Lock()
	defer q.packetMutex.Unlock()

	if q.NumPackets == 0 {
		return nil
	}

	packet := q.Packets[q.StartIndex]
	q.StartIndex = (q.StartIndex + 1) % PACKET_QUEUE_SIZE
	q.NumPackets--
	return packet
}
