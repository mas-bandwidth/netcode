package netcode

import (
	"bytes"
	"net"
)

type connectTokenEntry struct {
	mac     []byte
	address *net.UDPAddr
	time    int64
}

type encryptionEntry struct {
	expireTime int64
	lastAccess int64
	address    *net.UDPAddr
	sendKey    []byte
	recvKey    []byte
}

type ClientManager struct {
	maxClients int
	maxEntries int

	instances            []*ClientInstance
	connectTokensEntries []*connectTokenEntry
	cryptoEntries        []*encryptionEntry
	numCryptoEntries     int
}

func NewClientManager(maxClients int) *ClientManager {
	m := &ClientManager{}
	m.maxClients = maxClients

	m.maxEntries = maxClients * 8
	m.resetClientInstances()
	m.resetTokenEntries()
	m.resetCryptoEntries()
	return m
}

func (m *ClientManager) resetClientInstances() {
	m.instances = make([]*ClientInstance, m.maxClients)
	for i := 0; i < m.maxClients; i += 1 {
		instance := NewClientInstance()
		m.instances[i] = instance
	}
}

// preallocate the token buffers so we don't have to do nil checks
func (m *ClientManager) resetTokenEntries() {
	m.connectTokensEntries = make([]*connectTokenEntry, m.maxEntries)
	for i := 0; i < m.maxEntries; i += 1 {
		entry := &connectTokenEntry{}
		m.clearTokenEntry(entry)
		m.connectTokensEntries[i] = entry
	}
}

func (m *ClientManager) clearTokenEntry(entry *connectTokenEntry) {
	entry.mac = make([]byte, MAC_BYTES)
	entry.address = nil
	entry.time = -1
}

// preallocate the crypto entries so we don't have to do nil checks
func (m *ClientManager) resetCryptoEntries() {
	m.cryptoEntries = make([]*encryptionEntry, m.maxEntries)
	for i := 0; i < m.maxEntries; i += 1 {
		entry := &encryptionEntry{}
		m.clearCryptoEntry(entry)
		m.cryptoEntries[i] = entry
	}
}

func (m *ClientManager) clearCryptoEntry(entry *encryptionEntry) {
	entry.expireTime = -1
	entry.lastAccess = -1000
	entry.address = nil
	entry.sendKey = make([]byte, KEY_BYTES)
	entry.recvKey = make([]byte, KEY_BYTES)
}

func (m *ClientManager) FindFreeClientIndex() int {
	for i := 0; i < m.maxClients; i += 1 {
		if !m.instances[i].connected {
			return i
		}
	}
	return -1
}

func (m *ClientManager) FindClientIndexByAddress(addr *net.UDPAddr) int {
	for i := 0; i < m.maxClients; i += 1 {
		instance := m.instances[i]
		if instance.address != nil && instance.connected && addressEqual(instance.address, addr) {
			return i
		}
	}
	return -1
}

func (m *ClientManager) FindClientIndexById(clientId uint64) int {
	for i := 0; i < m.maxClients; i += 1 {
		instance := m.instances[i]
		if instance.address != nil && instance.connected && instance.clientId == clientId {
			return i
		}
	}
	return -1
}

func (m *ClientManager) FindEncryptionIndexByClientIndex(clientIndex int) int {
	if clientIndex < 0 || clientIndex > m.maxClients {
		return -1
	}

	return m.instances[clientIndex].encryptionIndex
}

func (m *ClientManager) FindOrAddTokenEntry(connectTokenMac []byte, addr *net.UDPAddr, time int64) bool {
	var oldestTime int64

	tokenIndex := -1
	oldestIndex := -1

	// find the matching entry for the token mac and the oldest token entry. constant time worst case. This is intentional!
	for i := 0; i < m.maxEntries; i += 1 {
		if bytes.Compare(m.connectTokensEntries[i].mac, connectTokenMac) == 0 {
			tokenIndex = i
		}

		if oldestIndex == -1 || m.connectTokensEntries[i].time < oldestTime {
			oldestTime = m.connectTokensEntries[i].time
			oldestIndex = i
		}
	}

	// if no entry is found with the mac, this is a new connect token. replace the oldest token entry.
	if tokenIndex == -1 {
		m.connectTokensEntries[oldestIndex].time = time
		m.connectTokensEntries[oldestIndex].address = addr
		m.connectTokensEntries[oldestIndex].mac = connectTokenMac
		return true
	}

	// allow connect tokens we have already seen from the same address
	if addressEqual(m.connectTokensEntries[tokenIndex].address, addr) {
		return true
	}

	return false
}

func (m *ClientManager) AddEncryptionMapping(connectToken *ConnectTokenPrivate, addr *net.UDPAddr, serverTime, expireTime int64) bool {
	for i := 0; i < m.maxEntries; i += 1 {
		entry := m.cryptoEntries[i]
		if entry.address != nil && addressEqual(entry.address, addr) && entry.lastAccess+TIMEOUT_SECONDS >= serverTime {
			entry.expireTime = expireTime
			entry.lastAccess = serverTime
			copy(entry.recvKey, connectToken.ClientKey)
			copy(entry.sendKey, connectToken.ServerKey)
			return true
		}
	}

	for i := 0; i < m.maxEntries; i += 1 {
		entry := m.cryptoEntries[i]
		if entry.lastAccess+TIMEOUT_SECONDS < serverTime || (entry.expireTime > 0 && entry.expireTime < serverTime) {
			entry.address = addr
			entry.expireTime = expireTime
			entry.lastAccess = serverTime
			copy(entry.recvKey, connectToken.ClientKey)
			copy(entry.sendKey, connectToken.ServerKey)
			if i+1 > m.numCryptoEntries {
				m.numCryptoEntries = i + 1
			}
			return true
		}
	}

	return false
}

func (m *ClientManager) FindEncryptionEntryIndex(addr *net.UDPAddr, serverTime int64) int {
	for i := 0; i < m.numCryptoEntries; i += 1 {
		entry := m.cryptoEntries[i]
		if entry == nil || entry.address == nil {
			continue
		}

		if addressEqual(entry.address, addr) && entry.lastAccess+TIMEOUT_SECONDS >= serverTime && (entry.expireTime < 0 || entry.expireTime >= serverTime) {
			entry.lastAccess = serverTime
			return i
		}
	}
	return -1
}

func (m *ClientManager) TouchEncryptionEntry(index int, addr *net.UDPAddr, serverTime int64) bool {
	if index < 0 || index > m.numCryptoEntries {
		return false
	}

	if !addressEqual(m.cryptoEntries[index].address, addr) {
		return false
	}

	m.cryptoEntries[index].lastAccess = serverTime
	return true
}

func (m *ClientManager) SetEncryptionEntryExpiration(index int, expireTime int64) bool {
	if index < 0 || index > m.numCryptoEntries {
		return false
	}

	m.cryptoEntries[index].expireTime = expireTime
	return true
}

func (m *ClientManager) RemoveEncryptionEntry(addr *net.UDPAddr, serverTime int64) bool {
	for i := 0; i < m.numCryptoEntries; i += 1 {
		entry := m.cryptoEntries[i]
		if !addressEqual(entry.address, addr) {
			continue
		}

		m.clearCryptoEntry(entry)

		if i+1 == m.numCryptoEntries {
			index := i - 1
			for index >= 0 {
				if m.cryptoEntries[index].lastAccess+TIMEOUT_SECONDS >= serverTime && (m.cryptoEntries[index].expireTime < 0 || m.cryptoEntries[index].expireTime > serverTime) {
					break
				}
				index--
			}
			m.numCryptoEntries = index + 1
		}

		return true
	}

	return false
}

func (m *ClientManager) GetEncryptionEntrySendKey(index int) []byte {
	return m.getEncryptionEntryKey(index, true)
}

func (m *ClientManager) GetEncryptionEntryRecvKey(index int) []byte {
	return m.getEncryptionEntryKey(index, false)
}

func (m *ClientManager) getEncryptionEntryKey(index int, sendKey bool) []byte {
	if index == -1 || index < 0 || index > m.numCryptoEntries {
		return nil
	}

	if sendKey {
		return m.cryptoEntries[index].sendKey
	}

	return m.cryptoEntries[index].recvKey
}

func (m *ClientManager) ConnectedClientCount() int {
	var count int

	for i := 0; i < m.maxClients; i += 1 {
		if m.instances[i].connected {
			count += 1
		}
	}

	return count
}
