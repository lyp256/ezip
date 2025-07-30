package ezip

import (
	"archive/zip"
	"bytes"
	"io"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestZipAesWriter(t *testing.T) {
	password := "foobar"
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	buf := &bytes.Buffer{}
	data := make([]byte, 1024*1024)
	random.Read(data)
	zw := zip.NewWriter(buf)
	fw, err := CreateAES256DeflateWrite(zw, "foobar", password, 9)
	require.NoError(t, err)
	_, err = fw.Write(data)
	require.NoError(t, err)
	err = fw.Close()
	require.NoError(t, err)
	err = zw.Close()
	require.NoError(t, err)

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	require.NoError(t, err)
	require.Len(t, zr.File, 1)
	fr, err := NewZipFileReader(zr.File[0], password)
	require.NoError(t, err)
	data2, err := io.ReadAll(fr)
	require.NoError(t, err)
	require.Equal(t, data, data2)
}
