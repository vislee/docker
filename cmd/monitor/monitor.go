package main

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/Sirupsen/logrus"
	systemdDaemon "github.com/coreos/go-systemd/daemon"
	"github.com/docker/docker/cli"
	"github.com/docker/docker/cli/command"
	cliflags "github.com/docker/docker/cli/flags"
	"github.com/docker/docker/pkg/jsonlog"
	"github.com/docker/docker/pkg/pidfile"
	"github.com/docker/docker/pkg/signal"
	"github.com/docker/docker/pkg/term"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type monitorOptions struct {
	common  *cliflags.CommonOptions
	flags   *pflag.FlagSet
	monitor string
	pidFile string
	logFile string
}

type monitorCli struct {
	flags *pflag.FlagSet
	ser   *MonitorServer
}

func (cli *monitorCli) start(opts *monitorOptions) error {
	rand.Seed(time.Now().Unix())
	stopc := make(chan bool)
	defer close(stopc)

	opts.common.SetDefaultOptions(opts.flags)
	cli.flags = opts.flags

	if opts.pidFile != "" {
		pf, err := pidfile.New(opts.pidFile)
		if err != nil {
			return fmt.Errorf("Error monitor starting: %v", err)
		}
		defer func() {
			logrus.Info("monitor exit, rm pidfile")
			if err := pf.Remove(); err != nil {
				logrus.Error(err)
			}
		}()
	}

	if opts.logFile != "" {
		file, err := os.OpenFile(opts.logFile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			return fmt.Errorf("Error monitor open logfile: %v", err)
		}
		logrus.SetOutput(file)
		defer func() {
			logrus.SetOutput(os.Stderr)
			file.Close()
		}()
	}

	logrus.SetFormatter(&logrus.TextFormatter{
		ForceColors:     false,
		TimestampFormat: jsonlog.RFC3339NanoFixed,
	})

	dockerCli := command.NewDockerCli(os.Stdin, os.Stdout, os.Stderr)
	cliOpt := &cliflags.ClientOptions{Common: opts.common}
	if err := dockerCli.Initialize(cliOpt); err != nil {
		fmt.Errorf("error: %s\n", err.Error())
		return err
	}

	dockerCli.Client().SetTimeout(10 * time.Second)

	ms := &MonitorServer{dockerCli: dockerCli, opts: opts}
	cli.ser = ms

	for i := 0; i < len(opts.common.Listens); i++ {
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

	signal.Trap(func() {
		cli.stop()
		<-stopc // wait for daemonCli.start() to return
	})

	serveAPIWait := make(chan error)
	go ms.Wait(serveAPIWait)
	notifySystem()
	errAPI := <-serveAPIWait
	if errAPI != nil {
		return fmt.Errorf("Shutting down due to ServeAPI error: %v", errAPI)
	}

	return nil
}

func (cli *monitorCli) stop() {
	cli.ser.Close()
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

func (m *MonitorServer) Close() {
	for _, srv := range m.servers {
		if err := srv.Close(); err != nil {
			logrus.Error(err)
		}
	}
}

func (m *MonitorServer) serveAPI() error {
	var chErrors = make(chan error, len(m.servers))
	for _, srv := range m.servers {
		srv.srv.Handler = m
		go func(srv *HTTPServer) {
			var err error
			logrus.Infof("Monitor API listen on %s", srv.l.Addr())
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
	case "/":
		m.Monitor(w, req)
	default:
		m.Fuck(w, req)
	}
}

func (m *MonitorServer) Ping(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, "pong\n")
}

func (m *MonitorServer) Fuck(w http.ResponseWriter, req *http.Request) {
	ss := []string{"The sadness will last forever.", "oh, Fuck. You get lost!!!", "In every man there is a fire, the passing of people only see the smoke.",
		"Normality is a paved road: It’s comfortable to walk, but no flowers grow on it.", "I know nothing with any certainty,but the sight of the stars makes me dream.",
		"Life must have the code and music."}
	i := rand.Intn(len(ss))
	io.WriteString(w, ss[i])
}

func (m *MonitorServer) Monitor(w http.ResponseWriter, req *http.Request) {
	args, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		logrus.Errorf("Monitor req ParseQuery: %s", err.Error())
		b, e := NewXml("docker", "monitor", err.Error(), err.Error(), "0").MarshalIndent()
		if e != nil {
			io.WriteString(w, e.Error())
			return
		}
		w.Header().Set("Content-Type", "text/xml;charset=utf-8")
		io.WriteString(w, string(b))
		return
	}
	service, ok := args["service"]
	if !ok {
		logrus.Errorf("Monitor req %s", "no service args")
		b, e := NewXml("docker", "monitor", "args error", "args error", "0").MarshalIndent()
		if e != nil {
			io.WriteString(w, e.Error())
			return
		}
		w.Header().Set("Content-Type", "text/xml;charset=utf-8")
		io.WriteString(w, string(b))
		return
	}

	ctx := context.Background()
	xml := &Xml{Res: make([]Resource, 0, len(service))}
	var container string = ""
	for _, itm := range service {
		src := path.Join(m.opts.monitor, itm)
		dst := fmt.Sprintf("/tmp/tmp_health_%s_%d", itm, rand.Int())
		btime := time.Now()
		container, err = m.dockerCli.Client().ContainerMonitor(ctx, src, container, dst, "200")
		td := time.Now().Sub(btime).String()
		if err != nil {
			logrus.Errorf("Monitor service %s resp: %s", itm, err.Error())
			xml.AppendItem("docker", itm, err.Error(), err.Error(), td)
		} else {
			logrus.Infof("Monitor service %s resp: test container %s ok", itm, container)
			xml.AppendItem("docker", itm, "", "", td)
		}
	}

	b, e := xml.MarshalIndent()
	if e != nil {
		logrus.Infof("Monitor resp: test container %s return xml error", container)
		io.WriteString(w, e.Error())
		return
	}
	w.Header().Set("Content-Type", "text/xml;charset=utf-8")
	io.WriteString(w, string(b))
}

func newMonitorCommand() *cobra.Command {
	opts := &monitorOptions{
		common: cliflags.NewCommonOptions(),
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
	flags.StringVar(&opts.monitor, "monitor", "/usr/local/sae/docker_monitor/bin/", "monitor exe file path")
	flags.StringVar(&opts.pidFile, "pidfile", "/data0/docker-monitor.pid", "monitor pidfile")
	flags.StringVar(&opts.logFile, "logfile", "/data0/logs/docker_monitor.log", "monitor logfile")

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
