package netcode

import (
	"crypto/rand"
	"math/big"
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

	token := NewConnectToken()
	if err := token.Generate(c.config, sequence, c.Id); err != nil {
		return err
	}

	return nil
}

func (c *Client) Connect() error {
	return nil
}

