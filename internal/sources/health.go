package sources

import (
	"errors"
	"fmt"
	"time"
)

type Health string

const (
	HealthEnabled      Health = "enabled"
	HealthDisabled     Health = "disabled"
	HealthDegraded     Health = "degraded"
	HealthAuthRequired Health = "auth-required"
	HealthRateLimited  Health = "rate-limited"
)

type SourceError struct {
	Health  Health
	Message string
	Err     error
}

func (e *SourceError) Error() string {
	if e == nil {
		return ""
	}

	if e.Err == nil {
		return e.Message
	}

	if e.Message == "" {
		return e.Err.Error()
	}

	return fmt.Sprintf("%s: %v", e.Message, e.Err)
}

func (e *SourceError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

type requestConfig struct {
	RetryBaseDelay time.Duration
}

var defaultRequestConfig = requestConfig{
	RetryBaseDelay: 2 * time.Second,
}

func ErrorHealth(err error) Health {
	var sourceErr *SourceError
	if errors.As(err, &sourceErr) && sourceErr.Health != "" {
		return sourceErr.Health
	}

	return HealthDegraded
}

func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	var sourceErr *SourceError
	if errors.As(err, &sourceErr) && sourceErr.Message != "" {
		return sourceErr.Message
	}

	return err.Error()
}

func degradedSourceError(message string, err error) error {
	return &SourceError{Health: HealthDegraded, Message: message, Err: err}
}

func authRequiredSourceError(message string, err error) error {
	return &SourceError{Health: HealthAuthRequired, Message: message, Err: err}
}

func rateLimitedSourceError(message string, err error) error {
	return &SourceError{Health: HealthRateLimited, Message: message, Err: err}
}

func retryBaseDelay(config requestConfig, attempt int) time.Duration {
	base := config.RetryBaseDelay
	if base <= 0 {
		base = defaultRequestConfig.RetryBaseDelay
	}

	return time.Duration(attempt+1) * base
}
