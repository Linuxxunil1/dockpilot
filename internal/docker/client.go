package docker

import (
	"github.com/moby/moby/client"
)

var CLI *client.Client

func Init() error {
	c, err := client.New(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return err
	}
	CLI = c
	return nil
}
