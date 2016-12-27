package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"time"

	"golang.org/x/net/context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/pkg/archive"
)

func (cli *Client) ContainerMonitor(ctx context.Context, srcPath, dstContainer, dstPath, status string) (string, error) {
	// 目标container为空，随机选择一个
	if dstContainer == "" {
		options := &types.ContainerListOptions{
			All:     false,
			Limit:   10,
			Size:    false,
			Filters: filters.NewArgs(),
		}

		containers, err := cli.ContainerList(ctx, *options)
		if err != nil {
			return "", fmt.Errorf("dstContainer(%s) error: %s", dstContainer, err.Error())
		}

		rand.Seed(time.Now().Unix())
		var ll = len(containers)
		for {
			ll -= 1
			idx := rand.Intn(len(containers) - 1)
			dstContainer = containers[idx].ID
			if containers[idx].State == "running" || ll == 0 {
				break
			}
		}
	}

	if dstContainer == "" || len(dstContainer) < 12 {
		return "", fmt.Errorf("no run container or container id too short")
	}

	// 拷贝文件到目标container
	dstInfo := archive.CopyInfo{Path: dstPath}
	srcInfo, err := archive.CopyInfoSourcePath(srcPath, true)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}

	srcArchive, err := archive.TarResource(srcInfo)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}
	defer srcArchive.Close()

	dstDir, preparedArchive, err := archive.PrepareArchiveCopy(srcArchive, srcInfo, dstInfo)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}
	defer preparedArchive.Close()

	options := types.CopyToContainerOptions{
		AllowOverwriteDirWithFile: false,
	}

	err = cli.CopyToContainer(ctx, dstContainer, dstDir, preparedArchive, options)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
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
	res, err := runMonitorExec(cli, dstContainer, execConfig)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}

	// 删除文件
	execConfig.Cmd = []string{"/bin/rm", "-f", dstPath}
	_, err = runMonitorExec(cli, dstContainer, execConfig)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}

	// 检查结果
	type monitorResp struct {
		Code    int
		Message string
	}
	var monitor monitorResp
	err = json.Unmarshal(res[8:], &monitor)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}

	st, err := strconv.Atoi(status)
	if err != nil {
		return "", fmt.Errorf("dstContainer(%s) error: %s", string([]byte(dstContainer[:12])), err.Error())
	}

	if monitor.Code != st {
		return "", fmt.Errorf("dstContainer(%s) message: %s", string([]byte(dstContainer[:12])), monitor.Message)
	}

	return string([]byte(dstContainer[:12])), nil
}

func runMonitorExec(client APIClient, dstContainer string, config *types.ExecConfig) ([]byte, error) {
	ctx := context.Background()

	response, err := client.ContainerExecCreate(ctx, dstContainer, *config)
	if err != nil {
		return nil, err
	}
	execID := response.ID
	if execID == "" {
		return nil, fmt.Errorf("exec ID empty")
	}

	resp, err := client.ContainerExecAttach(ctx, execID, *config)
	if err != nil {
		return nil, err
	}
	defer resp.Close()

	res, err := ioutil.ReadAll(resp.Reader)
	if err != nil {
		return nil, err
	}

	return res, nil
}
