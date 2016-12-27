package main

import (
	"time"
	"fmt"
	"os"
	"io"
	"net/http"
	"log"

	"golang.org/x/net/context"
	"github.com/docker/docker/cli/command"
	cliflags "github.com/docker/docker/cli/flags"
	"github.com/spf13/pflag"
)


type MonitorServer struct {
	dockerCli *command.DockerCli
	opts *cliflags.ClientOptions
}

func (m *MonitorServer) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.router(w, req)
}


func (m *MonitorServer) router(w http.ResponseWriter, req *http.Request) {
	switch req.URL.Path {
		case "/ping":
			m.Ping(w, req)
		case "/monitor":
			m.Monitor(w, req)
		default:
			m.Fuck(w, req)
	}
}

func (m *MonitorServer) Ping(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "pong\n")
}

func (m *MonitorServer) Fuck(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "Fuck\n")
}

func (m *MonitorServer) Monitor(w http.ResponseWriter, req *http.Request) {
	ctx := context.Background()
	err := m.dockerCli.Client().ContainerMonitor(ctx, m.opts.Monitor, "", "/tmp/tmp_health_monitor_net", "200")
	if err != nil {
		io.WriteString(w, err.Error())
	}
}

func main() {
	opts := cliflags.NewClientOptions()
	var flags pflag.FlagSet
	flags.StringVar(&opts.Monitor, "monitor", "/usr/local/sae/docker_monitor/bin/monitor_net", "monitor exe file")

	opts.Common.InstallFlags(&flags)
	opts.Common.SetDefaultOptions(&flags)
	err := flags.Parse(os.Args[1:])
	if err != nil {
		return
	}

	dockerCli := command.NewDockerCli(os.Stdin, os.Stdout, os.Stderr)
	if err := dockerCli.Initialize(opts); err != nil {
		fmt.Printf("error: %s\n", err.Error())
		return
	}

	dockerCli.Client().SetTimeout(10 * time.Second)

	m := &MonitorServer{dockerCli: dockerCli, opts:opts}

	s := &http.Server{
		Addr:           opts.Common.Listen,
		Handler:        m,
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   15 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())

	return
}
