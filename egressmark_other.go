//go:build !darwin && !linux

package main

import "syscall"

func markEgress(network, address string, c syscall.RawConn) error { return nil }
