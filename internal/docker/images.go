package docker

import (
	"context"
	"strings"

	"github.com/moby/moby/client"
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
	cs, _ := CLI.ContainerList(ctx, client.ContainerListOptions{All: true})
	for _, c := range cs.Items {
		usedIDs[c.ImageID] = true
	}

	imgs, err := CLI.ImageList(ctx, client.ImageListOptions{All: false})
	if err != nil {
		return nil, err
	}
	result := make([]ImageInfo, 0, len(imgs.Items))
	for _, img := range imgs.Items {
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
	_, err := CLI.ImageRemove(ctx, id, client.ImageRemoveOptions{Force: false, PruneChildren: true})
	return err
}

// PruneImages removes all images not used by any container (like `docker image prune -a`).
// Without dangling=false the daemon only removes untagged <none> images.
func PruneImages(ctx context.Context) (deleted int, freed int64, err error) {
	res, err := CLI.ImagePrune(ctx, client.ImagePruneOptions{Filters: make(client.Filters).Add("dangling", "false")})
	if err != nil {
		return 0, 0, err
	}
	return len(res.Report.ImagesDeleted), int64(res.Report.SpaceReclaimed), nil
}
