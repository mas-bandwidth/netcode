package netcode

import (
	"crypto/rand"
	"math/big"
	"time"
)

type Client struct {
	Id uint64
	config *Config
}

func NewClient(config *Config) *Client {
	c := &Client{config: config}
	return c
}

func (c *Client) Init(sequence uint64) error {
	id, err := rand.Int(rand.Reader, big.NewInt(64))
	if err != nil {
		return err
	}

	c.Id = id.Uint64()
	currentTimestamp := uint64(time.Now().Unix())

	token := NewConnectToken()
	if err := token.Generate(c.config, c.Id, currentTimestamp, sequence); err != nil {
		return err
	}

	return nil
}

func (c *Client) Connect() error {
	return nil
}

