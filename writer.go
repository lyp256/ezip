package ezip

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"sync/atomic"
	"time"
)

func CreateAES256DeflateWrite(zw *zip.Writer, name, password string, level int) (io.WriteCloser, error) {
	fh := &zip.FileHeader{
		Name:               name,
		Flags:              FlagsEncrypted | FlagsDataDescriptor | FlagsStrongEncryption,
		Method:             CompressMethodAES,
		Modified:           time.Now(),
		CRC32:              0,
		CompressedSize64:   0,
		UncompressedSize64: 0,
		Extra:              AESCryptoExtraField(),
	}

	raw, err := zw.CreateRaw(fh)
	if err != nil {
		return nil, err
	}

	var (
		rawSize, compressedSize uint64
	)
	aesWriter, err := NewAESWrite(AES256, WriteCounter(raw, &compressedSize), password)
	if err != nil {
		return nil, err
	}

	deflateWriter, err := flate.NewWriter(aesWriter, level)
	if err != nil {
		return nil, err
	}
	return &aes256Deflate{
		fileWriter:       raw,
		aesWriter:        aesWriter,
		deflateWriter:    deflateWriter,
		w:                WriteCounter(deflateWriter, &rawSize),
		fh:               fh,
		crc32:            crc32.NewIEEE(),
		compressedSize64: &compressedSize,
		rawSize64:        &rawSize,
		closed:           false,
	}, nil
}

type aes256Deflate struct {
	fileWriter       io.Writer
	aesWriter        io.WriteCloser
	deflateWriter    io.WriteCloser
	w                io.Writer
	fh               *zip.FileHeader
	crc32            hash.Hash32
	compressedSize64 *uint64
	rawSize64        *uint64
	closed           bool
}

func (a *aes256Deflate) Close() error {
	_ = a.deflateWriter.Close()
	_ = a.aesWriter.Close()
	a.fh.CRC32 = a.crc32.Sum32()
	a.fh.CompressedSize64 = *a.compressedSize64
	//nolint
	a.fh.CompressedSize = uint32(*a.compressedSize64)
	a.fh.UncompressedSize64 = *a.rawSize64
	//nolint
	a.fh.UncompressedSize = uint32(*a.rawSize64)
	a.closed = true
	return nil
}

func (a *aes256Deflate) Write(data []byte) (int, error) {
	if a.closed {
		return 0, fmt.Errorf("zip: write to closed aes256Deflate")
	}
	_, _ = a.crc32.Write(data)
	return a.w.Write(data)
}

func WriteCounter(w io.Writer, counter *uint64) io.Writer {
	return &writCounter{
		w: w,
		n: counter,
	}
}

type writCounter struct {
	w io.Writer
	n *uint64
}

func (w writCounter) Write(p []byte) (n int, err error) {
	n, err = w.w.Write(p)
	if w.n != nil {
		atomic.AddUint64(w.n, uint64(n))
	}
	return n, err
}
