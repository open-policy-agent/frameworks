package local

import "errors"

var (
	ErrModuleName = errors.New("invalid module name")
	ErrParse      = errors.New("unable to parse module")
	ErrCompile    = errors.New("unable to compile modules")
)
