package regorewriter

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/golang/glog"
)

// Sources represents all modules that have been fed into the
type Sources struct {
	Bases    []*Module
	Libs     []*Module
	TestData []*TestData
}

// sourceFile is an interface to normalize members of Sources to de-duplicate code involved in
// operating on all data in Sources.
type sourceFile interface {
	Reparent(old, new string) error
	Path() string
	Content() ([]byte, error)
}

// allModules is a convenience method for returning all the defined modules.
func (s *Sources) allSources() []sourceFile {
	var m []sourceFile
	appendMods := func(ms []*Module) {
		for _, module := range ms {
			m = append(m, module)
		}
	}
	appendMods(s.Bases)
	appendMods(s.Libs)
	for _, d := range s.TestData {
		m = append(m, d)
	}
	return m
}

// forAll runs
func (s *Sources) forAll(fn func(s sourceFile) error) error {
	for _, module := range s.Bases {
		if err := fn(module); err != nil {
			return err
		}
	}
	for _, module := range s.Libs {
		if err := fn(module); err != nil {
			return err
		}
	}
	for _, module := range s.TestData {
		if err := fn(module); err != nil {
			return err
		}
	}
	return nil
}

// Reparent will reparent the sources from the root specified at old to a root specified at new.
func (s *Sources) Reparent(old, new string) error {
	return s.forAll(func(s sourceFile) error {
		return s.Reparent(old, new)
	})
}

// Write will write the sources to the filesystem.
func (s *Sources) Write() error {
	return s.forAll(func(module sourceFile) error {
		for _, module := range s.allSources() {
			path := module.Path()
			content, err := module.Content()
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
				return err
			}
			glog.Infof("Writing %s", path)
			if err := ioutil.WriteFile(path, content, 0640); err != nil {
				return err
			}
		}
		return nil
	})
}

// AsMap returns a map of path to content as represented in Module.
func (s *Sources) AsMap() (map[string]string, error) {
	srcs := map[string]string{}
	err := s.forAll(func(s sourceFile) error {
		content, err := s.Content()
		if err != nil {
			return err
		}
		srcs[s.Path()] = string(content)
		return nil
	})
	return srcs, err
}
