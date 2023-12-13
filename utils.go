package proxy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// parse ports from string: 8000,8001,8002-8009
func ParsePorts(str string) (ports []uint64, err error) {
	var (
		p1, p2 uint64
		strs   []string
	)

	strs = strings.Split(str, ",")
	ports = make([]uint64, 0, len(strs))

	for _, v := range strs {
		list := strings.Split(strings.TrimSpace(v), "-")
		if len(list) == 0 {
			continue
		}

		if p1, err = strconv.ParseUint(strings.TrimSpace(list[0]), 10, 64); err != nil {
			return nil, err
		}

		if len(list) == 1 {
			p2 = p1
		} else {
			if p2, err = strconv.ParseUint(strings.TrimSpace(list[1]), 10, 64); err != nil {
				return nil, err
			}
		}

		if p1 > p2 {
			p1, p2 = p2, p1
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

func CreateMatcher(match string, logger Logger) func([]byte) {
	if match == "" {
		return nil
	}

	var (
		matchId uint64
		err     error
		re      *regexp.Regexp
	)

	if re, err = regexp.Compile(match); err != nil {
		logger.Warn("Invalid match regex: %s", err)
		return nil
	}

	logger.Info("Matching %s", re.String())

	return func(input []byte) {
		matches := re.FindAll(input, -1)

		for _, bts := range matches {
			matchId++
			logger.Info("Match #%d: %s", matchId, string(bts))
		}
	}
}

func CreateReplacer(replace string, logger Logger) func([]byte) []byte {
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
		logger.Warn("Invalid replace option")
		return nil
	}

	if re, err = regexp.Compile(before); err != nil {
		logger.Warn("Invalid replace regex: %s", err)
		return nil
	}

	repl := []byte(after)
	logger.Info("Replacing %s with %s", re.String(), repl)

	return func(input []byte) []byte {
		return re.ReplaceAll(input, repl)
	}
}
