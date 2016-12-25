package client

import (
	"time"
)
// APIClient is an interface that clients that talk with a docker server must implement.
type APIClient interface {
	CommonAPIClient
	apiClientExperimental
	SetTimeout(d time.Duration)
	GetTimeout() time.Duration
}

// Ensure that Client always implements APIClient.
var _ APIClient = &Client{}
