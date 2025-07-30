package ezip

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewZipFileReader(t *testing.T) {
	password := "foobar"
	dirs, err := os.ReadDir("testdata")
	require.NoError(t, err)
	for _, item := range dirs {
		if filepath.Ext(item.Name()) != ".zip" {
			continue
		}
		zf, err := os.Open(filepath.Join("testdata", item.Name()))
		require.NoError(t, err)
		defer func() { _ = zf.Close() }()
		fi, err := zf.Stat()
		require.NoError(t, err)
		zr, err := zip.NewReader(zf, fi.Size())
		require.NoError(t, err)
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			r, err := NewZipFileReader(f, password)
			require.NoError(t, err)
			data, err := io.ReadAll(r)
			require.NoError(t, err)
			t.Log(string(data))

		}
	}

}
