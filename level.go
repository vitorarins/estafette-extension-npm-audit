package main

import (
	"errors"

	"strings"
)

var ErrInvalidVulnLevel = errors.New("invalid vulnerability level, falling back to 'low'.")

type Level int

const (
	Info = iota
	Low
	Moderate
	High
	Critical
	None
)

var levelNames = []string{
	"info",
	"low",
	"moderate",
	"high",
	"critical",
	"none",
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
