package container

import (
	"math/rand"
	"time"
	"io/ioutil"
	"fmt"
	"strings"
	"encoding/json"
	"strconv"

	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	"github.com/docker/docker/client"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/archive"
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
		Use: `monitor SRC_PATH|- [CONTAINER]:DEST_PATH  STATUS`,
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
	logrus.Errorf("Info runMonitor: %s", "begin")

	srcPath := opts.source
	dstContainer, dstPath := splitCpArg(opts.destination)
	ctx := context.Background()

	client := dockerCli.Client()
	logrus.Errorf("Info timeout 1: %d", client.GetTimeout())
	client.SetTimeout(5 * time.Second)
	defer client.SetTimeout(0 * time.Second)

	logrus.Errorf("Info timeout 2: %d", client.GetTimeout())
	// 目标container为空，随机选择一个
	if dstContainer == "" {
		options := &types.ContainerListOptions{
			All:     false,
			Limit:   10,
			Size:    false,
			Filters: filters.NewArgs(),
		}

		containers, err := client.ContainerList(ctx, *options)
		if err != nil {
			logrus.Errorf("Error containerList: %s", err.Error())
			return err
		}

		rand.Seed(time.Now().Unix())
		var ll = len(containers)
		for {
			ll -= 1
			idx := rand.Intn(len(containers)-1)
			dstContainer = containers[idx].ID
			if containers[idx].State == "running" || ll == 0 {
				break
			}
		}
	}
	logrus.Debugf("Debug dstContainer: %s\n", dstContainer)

	// 拷贝文件到目标container
	dstInfo := archive.CopyInfo{Path: dstPath}
	srcInfo, err := archive.CopyInfoSourcePath(srcPath, true)
	if err != nil {
		logrus.Errorf("Error copyInfoSourcePath: %s", err.Error())
		return err
	}

	srcArchive, err := archive.TarResource(srcInfo)
	if err != nil {
		logrus.Errorf("Error tarResource: %s", err.Error())
		return err
	}
	defer srcArchive.Close()

	dstDir, preparedArchive, err := archive.PrepareArchiveCopy(srcArchive, srcInfo, dstInfo)
	if err != nil {
		logrus.Errorf("Error prepareArchiveCopy: %s", err.Error())
		return err
	}
	defer preparedArchive.Close()

	options := types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: false,
	}

	err = client.CopyToContainer(ctx, dstContainer, dstDir, preparedArchive, options)
	if err != nil {
		logrus.Errorf("Error dstContainer(%s) copyToContainer: %s", string([]byte(dstContainer[:10])), err.Error())
		return err
	}

	// 执行命令
	execConfig := &types.ExecConfig{
		Tty:          false,
		Cmd:          []string{dstPath},
		Detach:       false,
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  false,
	}
	res, err := runMonitorExec(client, dstContainer, execConfig)
	if err != nil {
		logrus.Warnf("Warn run file error. file: %s:%s error: %s\n", string([]byte(dstContainer[:10])), dstPath, err.Error())
		return err
	}
	logrus.Debugf("Debug rest: %s\n", string(res))

	// 删除文件
	execConfig.Cmd = []string{"/bin/rm", "-f", dstPath}
	_, err = runMonitorExec(client, dstContainer, execConfig)
	if err != nil {
		logrus.Warnf("Warn rm file error. file: %s:%s error: %s\n", string([]byte(dstContainer[:10])), dstPath, err.Error())
		return err
	}

	// 检查结果
	type monitorResp struct {
		Code      int
		Message   string
	}
	var monitor monitorResp
	err = json.Unmarshal(res[8:], &monitor)
	if err != nil {
		logrus.Errorf("Error dstContainer(%s) Unmarshal: %s res: %v strres: %s", string([]byte(dstContainer[:10])), err.Error(), res, string(res))
		return err
	}

	status, err := strconv.Atoi(opts.status)
	if err != nil {
		logrus.Errorf("Error dstContainer(%s) Atoi(%s) error %s", string([]byte(dstContainer[:10])), opts.status, err.Error())
		return err
	}

	if monitor.Code != status {
		return fmt.Errorf("err: dstContainer(%s) message: %s", string([]byte(dstContainer[:10])), monitor.Message)
	}

	return fmt.Errorf("ok: dstContainer(%s)", string([]byte(dstContainer[:10])))
}


func runMonitorExec(client client.APIClient, dstContainer string, config *types.ExecConfig) ([]byte, error) {
	ctx := context.Background()

	response, err := client.ContainerExecCreate(ctx, dstContainer, *config)
	if err != nil {
		logrus.Errorf("Error containerExecCreate: %s dstContainer: %s\n", err.Error(), dstContainer)
		return nil, err
	}
	execID := response.ID
	if execID == "" {
		logrus.Errorf("Error exec ID empty, dstContainer: %s \n", dstContainer)
		return nil, fmt.Errorf("exec ID empty")
	}
	logrus.Debugf("Debug exec ID %s\n", execID)

	resp, err := client.ContainerExecAttach(ctx, execID, *config)
	if err != nil {
		logrus.Errorf("Error containerExecAttach: %s", err.Error())
		return nil, err
	}
	defer resp.Close()

	res, err := ioutil.ReadAll(resp.Reader)
	if err != nil {
		logrus.Errorf("Error ReadAll: %s", err.Error())
		return nil, err
	}

	return res, nil
}

