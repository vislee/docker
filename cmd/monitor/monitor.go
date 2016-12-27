package main


import (
	"fmt"
	"os"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	cliflags "github.com/docker/docker/cli/flags"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/docker/pkg/pidfile"
	systemdDaemon "github.com/coreos/go-systemd/daemon"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)


type monitorOptions struct {
	common       *cliflags.CommonOptions
	flags        *pflag.FlagSet
	monitor      string
	pidFile      string
}


type monitorCli struct {
	flags      *pflag.FlagSet
	ser        *MonitorServer
}

func (cli *monitorCli) start(opts *monitorOptions) error {
	opts.common.SetDefaultOptions(opts.flags)
	cli.flags = opts.flags

	if opts.pidFile != "" {
		pf, err := pidfile.New(opts.pidFile)
		if err != nil {
			return fmt.Errorf("Error starting monitor: %v", err)
		}
		defer func() {
			if err := pf.Remove(); err != nil {
				logrus.Error(err)
			}
		}()
	}

	dockerCli := command.NewDockerCli(os.Stdin, os.Stdout, os.Stderr)
	cliOpt := &cliflags.ClientOptions{Common: opts.common}
	if err := dockerCli.Initialize(cliOpt); err != nil {
		fmt.Errorf("error: %s\n", err.Error())
		return err
	}

	dockerCli.Client().SetTimeout(10 * time.Second)


	ms := &MonitorServer{dockerCli: dockerCli, opts: opts}
	cli.ser = ms

	for i:=0; i<len(opts.common.Listens); i++ {
		protoAddr := opts.common.Listens[i]
		protoAddrParts := strings.SplitN(protoAddr, "://", 2)
		if len(protoAddrParts) != 2 {
			return fmt.Errorf("listen bad format %s, expected PROTO://ADDR", protoAddr)
		}

		proto := protoAddrParts[0]
		addr := protoAddrParts[1]

		ls, err := net.Listen(proto, addr)
		if err != nil {
			return fmt.Errorf("listen error: %s", err.Error())
		}

		ms.Accept(proto, ls)
	}

	serveAPIWait := make(chan error)
	go ms.Wait(serveAPIWait)
	notifySystem()
	errAPI := <-serveAPIWait
	if errAPI != nil {
		return fmt.Errorf("Shutting down due to ServeAPI error: %v", errAPI)
	}

	return nil
}


type HTTPServer struct {
	srv *http.Server
	l   net.Listener
}

// Serve starts listening for inbound requests.
func (s *HTTPServer) Serve() error {
	return s.srv.Serve(s.l)
}

// Close closes the HTTPServer from listening for the inbound requests.
func (s *HTTPServer) Close() error {
	return s.l.Close()
}

type MonitorServer struct {
	dockerCli *command.DockerCli
	opts      *monitorOptions
	servers   []*HTTPServer
}

func (m *MonitorServer) Wait(waitChan chan error) {
	if err := m.serveAPI(); err != nil {
		logrus.Errorf("ServeAPI error: %v", err)
		waitChan <- err
		return
	}
	waitChan <- nil
}

func (m *MonitorServer) Accept(addr string, listeners ...net.Listener) {
	for _, listener := range listeners {
		httpServer := &HTTPServer{
			srv: &http.Server{
				Addr: addr,
			},
			l: listener,
		}
		m.servers = append(m.servers, httpServer)
	}
}

func (m *MonitorServer) serveAPI() error {
	var chErrors = make(chan error, len(m.servers))
	for _, srv := range m.servers {
		srv.srv.Handler = m
		go func(srv *HTTPServer) {
			var err error
			logrus.Infof("API listen on %s", srv.l.Addr())
			if err = srv.Serve(); err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			chErrors <- err
		}(srv)
	}

	for i := 0; i < len(m.servers); i++ {
		err := <-chErrors
		if err != nil {
			return err
		}
	}

	return nil
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
	err := m.dockerCli.Client().ContainerMonitor(ctx, m.opts.monitor, "", "/tmp/tmp_health_monitor_net", "200")
	if err != nil {
		io.WriteString(w, err.Error())
	}
}

func newMonitorCommand() *cobra.Command {
	opts := &monitorOptions{
		common:       cliflags.NewCommonOptions(),
	}

	cmd := &cobra.Command{
		Use:           "monitor [OPTIONS]",
		Short:         "A monitor daemon.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cli.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			opts.flags = cmd.Flags()
			return runMonitor(opts)
		},
	}
	cli.SetupRootCommand(cmd)

	flags := cmd.Flags()
	flags.StringVar(&opts.monitor, "monitor", "/usr/local/sae/docker_monitor/bin/monitor-net", "monitor exe file")
	flags.StringVar(&opts.pidFile, "pidfile", "/data0/logs/docker-monitor.pid", "monitor pidfile")

	opts.common.InstallFlags(flags)

	return cmd
}

func runMonitor(opts *monitorOptions) error {

	mCli := &monitorCli{}

	stop, err := initService(mCli)
	if err != nil {
		logrus.Fatal(err)
	}

	if stop {
		return nil
	}

	err = mCli.start(opts)
	return err
}


func initService(mCli *monitorCli) (bool, error) {
	return false, nil
}

func notifySystem() {
	// Tell the init daemon we are accepting requests
	go systemdDaemon.SdNotify("READY=1")
}

func main() {
	// Set terminal emulation based on platform as required.
	_, stdout, stderr := term.StdStreams()
	logrus.SetOutput(stderr)

	cmd := newMonitorCommand()
	cmd.SetOutput(stdout)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "%s\n", err)
		os.Exit(1)
	}
}