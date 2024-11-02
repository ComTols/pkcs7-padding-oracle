package env

import (
	"os"
	"strconv"
)

type EnvironmentVar[T any] struct {
	name     string
	fallback T
}

var (
	Host = EnvironmentVar[string]{
		name:     "hostname",
		fallback: "127.0.0.1",
	}
	Port = EnvironmentVar[int]{
		name:     "port",
		fallback: 18652,
	}
)

func GetEnv[T any](key EnvironmentVar[T]) T {
	value := os.Getenv(key.name)
	if len(value) == 0 {
		return key.fallback
	}

	switch any(key.fallback).(type) {
	case string:
		return any(value).(T)
	case int:
		parsedValue, err := strconv.Atoi(value)
		if err == nil {
			return any(parsedValue).(T)
		}
	case bool:
		parsedValue, err := strconv.ParseBool(value)
		if err == nil {
			return any(parsedValue).(T)
		}
	}

	return key.fallback
}
