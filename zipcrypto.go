package ezip

import (
	"errors"
	"hash/crc32"
	"io"
)

type zipCrypto struct {
	password []byte
	Keys     [3]uint32
}

func newZipCrypto(passphrase []byte) *zipCrypto {
	z := &zipCrypto{}
	z.password = passphrase
	z.init()
	return z
}

func (z *zipCrypto) init() {
	z.Keys[0] = 0x12345678
	z.Keys[1] = 0x23456789
	z.Keys[2] = 0x34567890

	for i := 0; i < len(z.password); i++ {
		z.updateKeys(z.password[i])
	}
}

func (z *zipCrypto) updateKeys(byteValue byte) {
	z.Keys[0] = crc32update(z.Keys[0], byteValue)
	z.Keys[1] += z.Keys[0] & 0xff
	z.Keys[1] = z.Keys[1]*134775813 + 1
	z.Keys[2] = crc32update(z.Keys[2], (byte)(z.Keys[1]>>24))
}

func (z *zipCrypto) magicByte() byte {
	var t = z.Keys[2] | 2
	return byte((t * (t ^ 1)) >> 8)
}

func (z *zipCrypto) Encrypt(data []byte) {
	length := len(data)
	for i := 0; i < length; i++ {
		v := data[i]
		data[i] = v ^ z.magicByte()
		z.updateKeys(v)
	}
}

func (z *zipCrypto) Decrypt(cipher []byte) {
	for i, c := range cipher {
		v := c ^ z.magicByte()
		z.updateKeys(v)
		cipher[i] = v
	}
}

func crc32update(pCrc32 uint32, bval byte) uint32 {
	return crc32.IEEETable[(pCrc32^uint32(bval))&0xff] ^ (pCrc32 >> 8)
}

func NewZipCryptoReader(r io.Reader, password []byte) (io.Reader, error) {
	der := deCrypto{
		z: newZipCrypto(password),
		r: r,
	}
	_, err := der.Read(der.un[:])
	return &der, err
}

type deCrypto struct {
	z  *zipCrypto
	r  io.Reader
	un [12]byte
}

func (d *deCrypto) Read(p []byte) (n int, err error) {
	n, err = d.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, err
	}
	d.z.Decrypt(p[:n])
	return n, err
}
