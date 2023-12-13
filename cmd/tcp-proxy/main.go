package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	proxy "github.com/jpillora/go-tcp-proxy"
)

var (
	_Version = "0.1.0"
)

func main() {
	var (
		localAddr   string
		localPorts  []uint64
		remoteAddr  string
		remotePorts []uint64
		err         error
		config      *Config
		quit        chan os.Signal
		listener    *net.TCPListener
		listeners   []*net.TCPListener
		logger      proxy.Logger
	)

	config = NewConfig()

	flag.StringVar(&localAddr, "local", ":8080,8081,8082-8089", `local address`)
	flag.StringVar(&remoteAddr, "remote", "localhost:8000,8001,8002-8009", `remote address`)

	flag.StringVar(&config.Match, "match", "", "match regex (in the form 'regex')")
	flag.StringVar(&config.Replace, "replace", "", "replace regex (in the form 'regex~replacer')")
	flag.BoolVar(&config.Color, "color", false, "output ansi color")
	flag.BoolVar(&config.Nagles, "nagles", false, "disable nagles algorithm")
	flag.BoolVar(&config.Hex, "hex", false, "output hex")
	flag.BoolVar(&config.UnwrapTLS, "unwrap-tls", false, "remote connection with TLS exposed unencrypted locally")
	flag.BoolVar(&config.Verbose, "v", false, "display server actions")
	flag.BoolVar(&config.Veryverbose, "vv", false, "display server actions and all tcp data")

	flag.Parse()

	if config.Veryverbose {
		config.Verbose = true
	}

	logger = proxy.ColorLogger{
		Verbose: config.Verbose,
		Color:   config.Color,
	}

	if localPorts, err = parseAddr(&localAddr); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	if remotePorts, err = parseAddr(&remoteAddr); err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	if len(localPorts) != len(remotePorts) {
		logger.Error("The number of localPorts and remotePorts is not equal")
		os.Exit(1)
	}

	//
	listeners = make([]*net.TCPListener, 0, len(localPorts))
	for i := range localPorts {
		laddr := fmt.Sprintf("%s:%d", localAddr, localPorts[i])
		raddr := fmt.Sprintf("%s:%d", remoteAddr, remotePorts[i])

		if listener, err = run(laddr, raddr, config, logger); err != nil {
			logger.Error(err.Error())
			for _, listener = range listeners {
				_ = listener.Close()
				config.RunChan <- false
			}

			os.Exit(1)
		}

		listeners = append(listeners, listener)
	}

	for _ = range listeners {
		config.RunChan <- true
	}

	//
	quit = make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR2)

	select {
	case sig := <-quit:
		// if sig == syscall.SIGUSR2 {/* */}
		fmt.Fprintln(os.Stderr, "... received:", sig)
	}

	close(config.ExitChan)

	dur := 3 * time.Second
	logger.Warn("Close listeners in %s...", dur)
	time.Sleep(dur)

	for _, listener = range listeners {
		_ = listener.Close()
	}

	os.Exit(1)
}

func parseAddr(str *string) (ports []uint64, err error) {
	var (
		found   bool
		portStr string
	)

	if *str, portStr, found = strings.Cut(*str, ":"); !found {
		return nil, fmt.Errorf("missing ports: %q", *str)
	}

	return proxy.ParsePorts(portStr)
}

func run(localAddr string, remoteAddr string, config *Config, logger proxy.Logger) (
	listener *net.TCPListener, err error) {
	var (
		connId       uint64
		laddr, raddr *net.TCPAddr
	)

	if laddr, err = net.ResolveTCPAddr("tcp", localAddr); err != nil {
		return nil, fmt.Errorf("Failed to resolve local address: %w", err)
	}

	if raddr, err = net.ResolveTCPAddr("tcp", remoteAddr); err != nil {
		return nil, fmt.Errorf("Failed to resolve remote address: %s", err)
	}

	if listener, err = net.ListenTCP("tcp", laddr); err != nil {
		return nil, fmt.Errorf("Failed to open local port to listen: %s", err)
	}

	go func() {
		if ok := <-config.RunChan; !ok {
			return
		}

		logger.Info(
			"go-tcp-proxy (%s) proxing: localAddr=%q, remoteAddr=%q",
			_Version, localAddr, remoteAddr,
		)

		for {
			select {
			case <-config.ExitChan:
				return
			default:
			}

			var (
				p    *proxy.Proxy
				conn *net.TCPConn
				err  error
			)

			if conn, err = listener.AcceptTCP(); err != nil {
				logger.Error("Failed to accept connection: %s", err)
				continue
			}
			connId++

			if config.UnwrapTLS {
				logger.Info("Unwrapping TLS")
				p = proxy.NewTLSUnwrapped(conn, laddr, raddr, remoteAddr)
			} else {
				p = proxy.New(conn, laddr, raddr)
			}

			p.Matcher = proxy.CreateMatcher(config.Match, logger)
			p.Replacer = proxy.CreateReplacer(config.Replace, logger)
			p.Nagles, p.OutputHex = config.Nagles, config.Hex

			p.Log = proxy.ColorLogger{
				Verbose:     config.Verbose,
				VeryVerbose: config.Veryverbose,
				Prefix:      fmt.Sprintf("Connection %s(#%03d): ", conn.RemoteAddr(), connId),
				Color:       config.Color,
			}

			go p.Start()
		}
	}()

	return listener, nil
}

type Config struct {
	Match       string
	Replace     string
	Nagles      bool
	Hex         bool
	Color       bool
	UnwrapTLS   bool
	Verbose     bool
	Veryverbose bool
	RunChan     chan bool
	ExitChan    chan struct{}
}

func NewConfig() *Config {
	config := new(Config)

	config.RunChan = make(chan bool)
	config.ExitChan = make(chan struct{})

	return config
}
