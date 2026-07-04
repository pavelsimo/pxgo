package proxy

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
)

type replayableBody struct {
	data []byte
	path string
	size int64
}

func newReplayableBody(src io.ReadCloser) (*replayableBody, error) {
	if src == nil || src == http.NoBody {
		return &replayableBody{}, nil
	}
	defer src.Close()

	var buf bytes.Buffer
	n, err := io.CopyN(&buf, src, maxMemoryBody+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if errors.Is(err, io.EOF) && n <= maxMemoryBody {
		return &replayableBody{data: buf.Bytes(), size: n}, nil
	}

	file, err := os.CreateTemp("", "pxgo-body-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = file.Close()
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(buf.Bytes()); err != nil {
		return nil, err
	}
	copied, err := io.Copy(file, src)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	cleanup = false
	return &replayableBody{path: path, size: n + copied}, nil
}

func (b *replayableBody) Open() (io.ReadCloser, error) {
	if b == nil || b.size == 0 {
		return http.NoBody, nil
	}
	if b.path != "" {
		return os.Open(b.path)
	}
	return io.NopCloser(bytes.NewReader(b.data)), nil
}

func (b *replayableBody) Size() int64 {
	if b == nil {
		return 0
	}
	return b.size
}

func (b *replayableBody) Close() error {
	if b == nil || b.path == "" {
		return nil
	}
	err := os.Remove(b.path)
	b.path = ""
	return err
}
