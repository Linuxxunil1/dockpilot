package docker

import (
	"github.com/docker/docker/client"
)

var CLI *client.Client

func Init() error {
	c, err := client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return err
	}
	CLI = c
	return nil
}
