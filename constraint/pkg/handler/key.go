package handler

import "strings"

type Key []string

func (k Key) String() string {
	return strings.Join(k, "/")
}
