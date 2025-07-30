package ezip

import (
	"archive/zip"
	"compress/flate"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"

	"github.com/ulikunitz/xz"
)

func NewZipFileReader(file *zip.File, password string) (io.ReadCloser, error) {
	// 未加密
	if file.Flags&0x0001 == 0 {
		switch file.FileHeader.Method {
		case CompressMethodXZ:
			raw, err := file.OpenRaw()
			if err != nil {
				return nil, err
			}
			r, err := xz.NewReader(raw)
			return io.NopCloser(r), err
		default:
			return file.Open()
		}
	}
	//加密
	if password == "" {
		return nil, ErrInvalidPassword
	}
	raw, err := file.OpenRaw()
	if err != nil {
		return nil, err
	}
	var dest io.Reader
	switch file.FileHeader.Method {
	case CompressMethodStore, CompressMethodDeflate, CompressMethodXZ:
		dest, err = NewZipCryptoReader(raw, []byte(password))
		if err != nil {
			return nil, err
		}
		switch file.FileHeader.Method {
		case CompressMethodDeflate:
			dest = flate.NewReader(dest)
		case CompressMethodXZ:
			dest, err = xz.NewReader(dest)
			if err != nil {
				return nil, err
			}
		}
	case CompressMethodAES:
		ef, err := ExtraFields(file.Extra).Fields()
		if err != nil {
			return nil, err
		}
		aesExt := FindAESCryptoExtraField(ef)
		var (
			ae uint8  = 3
			cm uint16 = CompressMethodStore
		)
		if aesExt != nil {
			ae = aesExt.EncryptionStrength()
			cm = aesExt.CompressionMethod()
		}
		var keySize int
		switch ae {
		case AESCryptoEncryptionStrengthAES128:
			keySize = AES128
		case AESCryptoEncryptionStrengthAES192:
			keySize = AES192
		case AESCryptoEncryptionStrengthAES256:
			keySize = AES256

		}
		dest, err = NewAESReader(keySize, raw, password)
		if err != nil {
			return nil, err
		}
		switch cm {
		case CompressMethodStore:
		case CompressMethodDeflate:
			dest = flate.NewReader(dest)
		case CompressMethodXZ:
			dest, err = xz.NewReader(dest)
			if err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupport compress method:%d", cm)
		}
	}
	if file.FileHeader.CRC32 != 0 {
		dest = WithHashVerifyReader(dest, crc32.NewIEEE(), file.FileHeader.CRC32)
	}
	return io.NopCloser(dest), err
}

func WithHashVerifyReader(r io.Reader, hash32 hash.Hash32, sum uint32) io.Reader {
	return &hash32VerifyReader{
		r:      r,
		sum:    sum,
		hash32: crc32.NewIEEE(),
	}
}

type hash32VerifyReader struct {
	r      io.Reader
	sum    uint32
	hash32 hash.Hash32
}

func (c *hash32VerifyReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.hash32 != nil {
		_, _ = c.hash32.Write(p[:n])
		if errors.Is(err, io.EOF) {
			if c.hash32.Sum32() != c.sum {
				return n, fmt.Errorf("hash32 verify failed")
			}
		}
	}
	return n, err
}
