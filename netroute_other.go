//go:build !darwin

package main

import "fmt"

func defaultRouteInfo() (gateway, ifaceName string, err error) {
	return "", "", fmt.Errorf("not supported on this platform")
}
