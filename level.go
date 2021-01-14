package main

import (
	"errors"

	"strings"
)

var ErrInvalidVulnLevel = errors.New("invalid vulnerability level, falling back to 'low'.")

type Level int

const (
	LevelNone Level = iota
	LevelLow
	LevelModerate
	LevelHigh
	LevelCritical
)

var levelNames = []string{
	"none",
	"low",
	"moderate",
	"high",
	"critical",
}

func (p Level) String() string {
	return levelNames[p]
}

func ToLevel(level string) (Level, error) {
	for i, name := range levelNames {
		if strings.EqualFold(name, level) {
			return Level(i), nil
		}
	}
	return LevelLow, ErrInvalidVulnLevel
}
