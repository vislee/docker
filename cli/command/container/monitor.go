package container

import (
	"fmt"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/spf13/cobra"
)

type monitorOptions struct {
	source      string
	destination string
	status      string
}

func NewMonitorCommand(dockerCli *command.DockerCli) *cobra.Command {
	var opts monitorOptions

	cmd := &cobra.Command{
		Use:   `monitor SRC_PATH|- [CONTAINER]:DEST_PATH  STATUS`,
		Short: "Copy a monitor bin to container and check the resp",
		Long: strings.Join([]string{
			"Copy a monitor file to container and check the resp\n\n",
			"",
		}, ""),
		Args: cli.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			if args[0] == "" {
				return fmt.Errorf("source can not be empty")
			}
			if args[1] == "" {
				return fmt.Errorf("destination can not be empty")
			}
			if args[2] == "" {
				return fmt.Errorf("status can not be empty")
			}
			opts.source = args[0]
			opts.destination = args[1]
			opts.status = args[2]
			return runMonitor(dockerCli, opts)
		},
	}

	return cmd
}

func runMonitor(dockerCli *command.DockerCli, opts monitorOptions) error {
	srcPath := opts.source
	dstContainer, dstPath := splitCpArg(opts.destination)
	ctx := context.Background()

	client := dockerCli.Client()
	client.SetTimeout(10 * time.Second)
	defer client.SetTimeout(0 * time.Second)

	container, err := client.ContainerMonitor(ctx, srcPath, dstContainer, dstPath, opts.status)
	if err != nil {
		return err
	}

	return fmt.Errorf("test container %s ok", container)
}
