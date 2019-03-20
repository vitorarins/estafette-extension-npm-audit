package main

import (
	"errors"
	"strings"
)

var ErrInvalidVulnLevel = errors.New("invalid vulnerability level")

type Level int

const (
	Info = iota
	Low
	Moderate
	High
	Critical
)

var levelNames = []string{
	"info",
	"low",
	"moderate",
	"high",
	"critical",
}

func (p Level) String() string {
	return levelNames[p]
}

func VulnLevel(level string) (Level, error) {
	for i, name := range levelNames {
		if strings.EqualFold(name, level) {
			return Level(i), nil
		}
	}
	return Low, ErrInvalidVulnLevel
}

// func isEnabled(level Level, module string) bool {
// 	return level <= l.GetLevel(module)
// }
