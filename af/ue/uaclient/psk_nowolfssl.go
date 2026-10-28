//go:build !wolfssl

package uaclient

import "context"

// PSKBuilt is false: this client has no PSK profiles.
const PSKBuilt = false

// PSKSession is not available without wolfSSL.
type PSKSession struct{}

// NewPSKSession returns ErrNoWolfSSL.
func NewPSKSession(PSKConfig) (*PSKSession, error) { return nil, ErrNoWolfSSL }

// Establish returns ErrNoWolfSSL.
func (*PSKSession) Establish(context.Context) (Result, error) { return Result{}, ErrNoWolfSSL }

// Close does nothing.
func (*PSKSession) Close() {}

// DTLSSession is not available without wolfSSL.
type DTLSSession struct{}

// NewDTLSSession returns ErrNoWolfSSL.
func NewDTLSSession(PSKConfig) (*DTLSSession, error) { return nil, ErrNoWolfSSL }

// Establish returns ErrNoWolfSSL.
func (*DTLSSession) Establish(context.Context) (Result, error) { return Result{}, ErrNoWolfSSL }

// Close does nothing.
func (*DTLSSession) Close() {}
