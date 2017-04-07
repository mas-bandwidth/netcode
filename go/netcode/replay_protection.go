package netcode

// Our type to hold replay protection of packet sequences
type ReplayProtection struct {
	MostRecentSequence uint64   // last sequence recv'd
	ReceivedPacket     []uint64 // slice of REPLAY_PROTECTION_BUFFER_SIZE worth of packet sequences
}

// Initializes a new ReplayProtection with the ReceivedPacket buffer elements all set to 0xFFFFFFFFFFFFFFFF
func NewReplayProtection() *ReplayProtection {
	r := &ReplayProtection{}
	r.ReceivedPacket = make([]uint64, REPLAY_PROTECTION_BUFFER_SIZE)
	r.Reset()
	return r
}

// Clears out the most recent sequence and resets the entire packet buffer to 0xFFFFFFFFFFFFFFFF
func (r *ReplayProtection) Reset() {
	r.MostRecentSequence = 0
	clearPacketBuffer(r.ReceivedPacket)
}

// Tests that the sequence has not already been recv'd, adding it to the buffer if it's new.
func (r *ReplayProtection) AlreadyReceived(sequence uint64) int {
	if sequence&(uint64(1<<63)) != 0 {
		return 0
	}

	if sequence+REPLAY_PROTECTION_BUFFER_SIZE <= r.MostRecentSequence {
		return 1
	}

	if sequence > r.MostRecentSequence {
		r.MostRecentSequence = sequence
	}

	index := sequence % REPLAY_PROTECTION_BUFFER_SIZE

	if r.ReceivedPacket[index] == 0xFFFFFFFFFFFFFFFF {
		r.ReceivedPacket[index] = sequence
		return 0
	}

	if r.ReceivedPacket[index] >= sequence {
		return 1
	}

	r.ReceivedPacket[index] = sequence
	return 0
}

func clearPacketBuffer(packets []uint64) {
	for i := 0; i < len(packets); i += 1 {
		packets[i] = 0xFFFFFFFFFFFFFFFF
	}
}
