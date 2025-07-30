package ezip

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
)

const (
	AES128 = 16
	AES192 = 24
	AES256 = 32
)

func NewAESReader(size int, raw io.Reader, password string) (io.Reader, error) {
	switch size {
	case AES128, AES192, AES256:
	default:
		return nil, ErrInvalidAESKeySize

	}
	header := make([]byte, 18)
	n, err := raw.Read(header)
	if err != nil {
		return nil, err
	}
	if len(header) != n {
		return nil, fmt.Errorf("invalid zip file data")
	}
	salt := header[:16]
	iv := header[16:]

	keyData, err := pbkdf2.Key(sha1.New, password, salt, 1000, size*2+2)
	if err != nil {
		return nil, err
	}
	deKey := keyData[:size]
	hmacKey := keyData[size : size*2]
	pv := keyData[len(keyData)-2:]
	_ = hmacKey
	if subtle.ConstantTimeCompare(iv, pv) == 0 {
		return nil, ErrInvalidPassword
	}
	aesDec, err := aes.NewCipher(deKey)
	if err != nil {
		return nil, err
	}

	return &aes256DecReader{
		preReadBuf:    make([]byte, 10),
		preReadBufLen: 0,
		raw:           raw,
		cipher:        WinZipCTR(aesDec),
		hash:          hmac.New(sha1.New, hmacKey),
	}, nil
}

type aes256DecReader struct {
	preReadBuf    []byte
	preReadBufLen int
	raw           io.Reader
	cipher        cipher.Stream
	hash          hash.Hash
}

func (r *aes256DecReader) Read(dest []byte) (n int, err error) {
	destLen := 0
	// 将预读数据填充到 dest
	if r.preReadBufLen != 0 {
		n = copy(dest, r.preReadBuf[:r.preReadBufLen])
		copy(r.preReadBuf, r.preReadBuf[n:r.preReadBufLen])
		r.preReadBufLen -= n
		destLen += n
	}
	// 读取数据
	if destLen < len(dest) {
		n, err = r.raw.Read(dest[destLen:])
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		destLen += n
	}
	// 预读取数据
	for {
		if r.preReadBufLen < len(r.preReadBuf) {
			n, err = r.raw.Read(r.preReadBuf[r.preReadBufLen:])
			if err != nil && !errors.Is(err, io.EOF) {
				return 0, err
			}
			r.preReadBufLen += n
		}
		// 确保完整的预读取数据
		if r.preReadBufLen == len(r.preReadBuf) || err != nil {
			break
		}
	}
	// 读完处理
	if errors.Is(err, io.EOF) {
		if destLen+len(r.preReadBuf) < 10 {
			return 0, fmt.Errorf("invalid zip file data")
		}
		//数据会流，确保验证数据完整
		if r.preReadBufLen != len(r.preReadBuf) {
			l := len(r.preReadBuf) - r.preReadBufLen
			tmp := make([]byte, len(r.preReadBuf))
			copy(tmp, dest[destLen-l:destLen])
			destLen -= l
			copy(tmp[l:], r.preReadBuf[:r.preReadBufLen])
			r.preReadBufLen += l
			copy(r.preReadBuf, tmp)
		}
	}
	// 解密数据
	_, _ = r.hash.Write(dest[:destLen])
	r.cipher.XORKeyStream(dest[:destLen], dest[:destLen])
	// 计算 hash
	if errors.Is(err, io.EOF) {
		hmacSum := r.hash.Sum(nil)
		l := len(r.preReadBuf)
		if l > len(hmacSum) {
			l = len(hmacSum)
		}
		if !bytes.Equal(hmacSum[:l], r.preReadBuf) {
			return 0, fmt.Errorf("aes verify failed")
		}
	}
	return destLen, err
}

func NewAESWrite(size int, w io.Writer, password string) (io.WriteCloser, error) {
	switch size {
	case AES128, AES192, AES256:
	default:
		return nil, ErrInvalidAESKeySize
	}
	header := make([]byte, 18)
	salt := header[:16]
	_, _ = rand.Read(salt)
	iv := header[16:]

	keyData, err := pbkdf2.Key(sha1.New, password, salt, 1000, size*2+2)
	if err != nil {
		return nil, err
	}
	deKey := keyData[:size]
	hmacKey := keyData[size : size*2]
	pv := keyData[len(keyData)-2:]
	copy(iv, pv)

	// wirte header
	n, err := w.Write(header)
	if err != nil {
		return nil, err
	}
	if len(header) != n {
		return nil, fmt.Errorf("write aes header failed")
	}

	aesCipher, err := aes.NewCipher(deKey)
	if err != nil {
		return nil, err
	}

	return &aes256Writer{
		raw:    w,
		cipher: WinZipCTR(aesCipher),
		hash:   hmac.New(sha1.New, hmacKey),
	}, nil
}

type aes256Writer struct {
	raw    io.Writer
	cipher cipher.Stream
	hash   hash.Hash
}

func (a *aes256Writer) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	a.cipher.XORKeyStream(buf, p)
	_, _ = a.hash.Write(buf)
	return a.raw.Write(buf)
}

func (a *aes256Writer) Close() error {
	buf := a.hash.Sum(nil)
	_, err := a.raw.Write(buf[:10])
	return err
}
