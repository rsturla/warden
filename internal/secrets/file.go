package secrets

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"strings"
)

type FileSource struct {
	root *os.Root
}

func NewFileSource(dir string) (*FileSource, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	return &FileSource{root: root}, nil
}

func (s *FileSource) Name() string { return "file" }

func (s *FileSource) Resolve(_ context.Context, name string) (string, bool, error) {
	data, err := s.root.ReadFile(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	return strings.TrimSpace(string(data)), true, nil
}

func (s *FileSource) Close() error {
	return s.root.Close()
}
