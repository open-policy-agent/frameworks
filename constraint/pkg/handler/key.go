package handler

import "strings"

type StoragePath []string

func (p StoragePath) String() string {
	return strings.Join(p, "/")
}
