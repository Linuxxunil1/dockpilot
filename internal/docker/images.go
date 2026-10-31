package docker

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
)

type ImageInfo struct {
	ID      string   `json:"id"`
	ShortID string   `json:"short_id"`
	Tags    []string `json:"tags"`
	Size    int64    `json:"size"`
	Created int64    `json:"created"`
	InUse   bool     `json:"in_use"`
}

func ListImages(ctx context.Context) ([]ImageInfo, error) {
	usedIDs := map[string]bool{}
	cs, _ := CLI.ContainerList(ctx, containerListAll())
	for _, c := range cs {
		usedIDs[c.ImageID] = true
	}

	imgs, err := CLI.ImageList(ctx, image.ListOptions{All: false})
	if err != nil {
		return nil, err
	}
	result := make([]ImageInfo, 0, len(imgs))
	for _, img := range imgs {
		shortID := img.ID
		if strings.HasPrefix(shortID, "sha256:") {
			shortID = shortID[7:]
		}
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}
		result = append(result, ImageInfo{
			ID:      img.ID,
			ShortID: shortID,
			Tags:    img.RepoTags,
			Size:    img.Size,
			Created: img.Created,
			InUse:   usedIDs[img.ID],
		})
	}
	return result, nil
}

func DeleteImage(ctx context.Context, id string) error {
	_, err := CLI.ImageRemove(ctx, id, image.RemoveOptions{Force: false, PruneChildren: true})
	return err
}

// PruneImages removes all images not used by any container (like `docker image prune -a`).
// Without dangling=false the daemon only removes untagged <none> images.
func PruneImages(ctx context.Context) (deleted int, freed int64, err error) {
	report, err := CLI.ImagesPrune(ctx, filters.NewArgs(filters.Arg("dangling", "false")))
	if err != nil {
		return 0, 0, err
	}
	return len(report.ImagesDeleted), int64(report.SpaceReclaimed), nil
}

func containerListAll() container.ListOptions {
	return container.ListOptions{All: true}
}
