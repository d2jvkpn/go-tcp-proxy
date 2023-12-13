package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	proxy "github.com/jpillora/go-tcp-proxy"
)

var (
	_Version = "0.1.0"
	_Logger  proxy.ColorLogger
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
	)

	config = NewConfig()

	flag.StringVar(&localAddr, "localAddr", ":8080", "local address")
	flag.StringVar(&remoteAddr, "remoteAddr", "localhost:8000", "remote address")

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

	_Logger = proxy.ColorLogger{
		Verbose: config.Verbose,
		Color:   config.Color,
	}

	if localPorts, err = parseAddr(&localAddr); err != nil {
		_Logger.Warn(err.Error())
		os.Exit(1)
	}

	if remotePorts, err = parseAddr(&remoteAddr); err != nil {
		_Logger.Warn(err.Error())
		os.Exit(1)
	}

	if len(localPorts) != len(remotePorts) {
		_Logger.Warn("The number of localPorts and remotePorts is not equal")
		os.Exit(1)
	}

	//
	listeners = make([]*net.TCPListener, 0, len(localPorts))
	for i := range localPorts {
		laddr := fmt.Sprintf("%s:%d", localAddr, localPorts[i])
		raddr := fmt.Sprintf("%s:%d", remoteAddr, remotePorts[i])

		if listener, err = run(laddr, raddr, config); err != nil {
			_Logger.Warn(err.Error())
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
	case sig := <-quit: // sig := <-quit:
		// if sig == syscall.SIGUSR2 {...}
		fmt.Println("... received:", sig)
		close(config.ExitChan)
	}

	_Logger.Warn("Close listeners...")
	time.Sleep(3 * time.Second)
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

	return parsePortRange(portStr)
}

func parsePortRange(str string) (ports []uint64, err error) {
	var (
		p1, p2 uint64
		strs   []string
	)

	strs = strings.Split(str, ",")
	if len(strs) == 0 {
		return nil, fmt.Errorf("invalid ports: %s", str)
	}

	ports = make([]uint64, 0, len(strs))

	for _, v := range strs {
		list := strings.Split(strings.TrimSpace(v), "-")
		if len(list) == 0 {
			continue
		}
		if len(list) == 1 {
			list = append(list, list[0])
		}

		if p1, err = strconv.ParseUint(strings.TrimSpace(list[0]), 10, 64); err != nil {
			return nil, err
		}

		if p2, err = strconv.ParseUint(strings.TrimSpace(list[1]), 10, 64); err != nil {
			return nil, err
		}

		for p := p1; p <= p2; p++ {
			ports = append(ports, p)
		}
	}

	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports")
	}

	return ports, nil
}

func run(localAddr string, remoteAddr string, config *Config) (
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
		ok := <-config.RunChan
		if !ok {
			return
		}

		_Logger.Info(
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
				_Logger.Warn("Failed to accept connection: %s", err)
				continue
			}
			connId++

			if config.UnwrapTLS {
				_Logger.Info("Unwrapping TLS")
				p = proxy.NewTLSUnwrapped(conn, laddr, raddr, remoteAddr)
			} else {
				p = proxy.New(conn, laddr, raddr)
			}

			p.Matcher = createMatcher(config.Match)
			p.Replacer = createReplacer(config.Replace)
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

func createMatcher(match string) func([]byte) {
	if match == "" {
		return nil
	}

	var (
		matchId uint64
		err     error
		re      *regexp.Regexp
	)

	if re, err = regexp.Compile(match); err != nil {
		_Logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	_Logger.Info("Matching %s", re.String())

	return func(input []byte) {
		matches := re.FindAll(input, -1)

		for _, bts := range matches {
			matchId++
			_Logger.Info("Match #%d: %s", matchId, string(bts))
		}
	}
}

func createReplacer(replace string) func([]byte) []byte {
	if replace == "" {
		return nil
	}

	var (
		before string
		after  string
		found  bool
		err    error
		re     *regexp.Regexp
	)

	//split by / (TODO: allow slash escapes)
	// parts := strings.Split(replace, "~")
	if before, after, found = strings.Cut(replace, "~"); !found {
		_Logger.Warn("Invalid replace option")
		return nil
	}

	if re, err = regexp.Compile(before); err != nil {
		_Logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(after)

	_Logger.Info("Replacing %s with %s", re.String(), repl)
	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}
