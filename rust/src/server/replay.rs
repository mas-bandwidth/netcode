const REPLAY_BUFFER_SIZE: usize = 256;
const EMPTY_ENTRY: u64 = 0xFFFFFFFFFFFFFFFF;

pub struct ReplayProtection {
    most_recent_sequence: u64,
    received_packet: [u64; REPLAY_BUFFER_SIZE]
}

impl Clone for ReplayProtection {
    fn clone(&self) -> ReplayProtection {
        ReplayProtection {
            most_recent_sequence: self.most_recent_sequence,
            received_packet: self.received_packet
        }
    }
}

impl ReplayProtection {
    pub fn new() -> ReplayProtection {
        ReplayProtection {
            most_recent_sequence: 0,
            received_packet: [EMPTY_ENTRY; REPLAY_BUFFER_SIZE]
        }
    }

    pub fn packet_already_received(&mut self, sequence: u64) -> bool {
        if sequence & (1 << 63) == (1 << 63) {
            return false;
        }

        if sequence + (REPLAY_BUFFER_SIZE as u64) <= self.most_recent_sequence {
            return true
        }
        
        if sequence > self.most_recent_sequence {
            self.most_recent_sequence = sequence;
        }

        let index = sequence as usize % REPLAY_BUFFER_SIZE;

        if self.received_packet[index] == EMPTY_ENTRY {
            self.received_packet[index] = sequence;
            return false
        }

        if self.received_packet[index] >= sequence {
            return true
        }
        
        self.received_packet[index] = sequence;

        false
    }
}

#[test]
fn test_replay_protection() {
    for _ in 0..2 {
        let mut replay_protection = ReplayProtection::new();

        assert_eq!(replay_protection.most_recent_sequence, 0);

        // sequence numbers with high bit set should be ignored
        assert!(!replay_protection.packet_already_received(1<<63));
        assert_eq!(replay_protection.most_recent_sequence, 0);

        // the first time we receive packets, they should not be already received
        const MAX_SEQUENCE: u64 = REPLAY_BUFFER_SIZE as u64 * 4;

        for sequence in 0..MAX_SEQUENCE {
            assert!(!replay_protection.packet_already_received(sequence));
        }

        // old packets outside buffer should be considered already received
        assert!(replay_protection.packet_already_received(0));

        // packets received a second time should be flagged already received
        for sequence in MAX_SEQUENCE-10..MAX_SEQUENCE {
            assert!(replay_protection.packet_already_received(sequence));
        }

        // jumping ahead to a much higher sequence should be considered not already received
        assert!(!replay_protection.packet_already_received(MAX_SEQUENCE + REPLAY_BUFFER_SIZE as u64));

        // old packets should be considered already received
        for sequence in 0..MAX_SEQUENCE {
            assert!(replay_protection.packet_already_received(sequence));
        }
    }
}