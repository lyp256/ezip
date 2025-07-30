package ezip

import (
	"encoding/binary"
	"fmt"
	"time"
)

const (
	FlagsEncrypted = 1 << iota
	FlagsCompressionOption1
	FlagsCompressionOption2
	FlagsDataDescriptor
	_
	_
	FlagsStrongEncryption
	_
	_
	_
	_
	FlagsLanguageEncoding
)

const (
	ExtraHeaderZip64          = 0x0001 //ZIP64扩展信息
	ExtraHeaderNTFSInfo       = 0x000a //NTFS扩展属性（时间戳）
	ExtraHeaderUnix           = 0x000d //Unix扩展属性（权限）
	ExtraHeaderCert           = 0x0017 //文件级证书
	ExtraHeaderAESCrypto      = 0x9901 //：AES加密信息
	ExtraHeaderFilenameCrypto = 0x9902 //：文件名称加密信息 =
)

const (
	CompressMethodStore   = 0x00
	CompressMethodXZ      = 0x005F
	CompressMethodDeflate = 0x0008
	CompressMethodAES     = 0x0063
)

// ExtraNTFSInfo
// +---------------------+-----------------------+
// | 字段                | 描述                  |
// +---------------------+-----------------------+
// | Reserved            | 4 (固定为0)           |
// | Tag ID (0x0001)     | 2                    |
// | Tag Size (24)       | 2                    |
// | Mtime (修改时间)     | 8 (FileTime 格式)     |
// | Atime (访问时间)     | 8 (FileTime 格式)     |
// | Ctime (创建时间)     | 8 (FileTime 格式)     |
// +---------------------+-----------------------+
type ExtraNTFSInfo []byte

func (e ExtraNTFSInfo) Reserved() uint32 { return binary.LittleEndian.Uint32(e) }
func (e ExtraNTFSInfo) TagID() uint16    { return binary.LittleEndian.Uint16(e[4:]) }
func (e ExtraNTFSInfo) TagSize() uint16  { return binary.LittleEndian.Uint16(e[6:]) }
func (e ExtraNTFSInfo) Mtime() uint64    { return binary.LittleEndian.Uint64(e[8:]) }
func (e ExtraNTFSInfo) Atime() uint64    { return binary.LittleEndian.Uint64(e[16:]) }
func (e ExtraNTFSInfo) Ctime() uint64    { return binary.LittleEndian.Uint64(e[24:]) }

var fileTimeEra = time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

func FileTime(f uint64) time.Time {
	if f == 0 {
		return time.Time{}
	}
	const day = uint64(time.Hour) * 24
	d := (f / day) * 100
	ns := (f % day) * 100

	return fileTimeEra.AddDate(0, 0, int(d)).Add(time.Duration(ns))
}

// ExtraZip64 struct
// +---------------------+-----------------------+
// | 字段                | 长度（字节）          |
// +---------------------+-----------------------+
// | Original Size       | 8 (可选)              |
// | Compressed Size     | 8 (可选)              |
// | Local Header Offset | 8 (可选)              |
// | Disk Number         | 4 (可选)              |
// +---------------------+-----------------------+
type ExtraZip64 []byte

func (e ExtraZip64) OriginalSize() uint64 {
	if len(e) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(e)
}
func (e ExtraZip64) CompressedSize() uint64 {
	if len(e) < 16 {
		return 0
	}
	return binary.LittleEndian.Uint64(e[8:])
}
func (e ExtraZip64) LocalHeaderOffset() uint64 {
	if len(e) < 24 {
		return 0
	}
	return binary.LittleEndian.Uint64(e[16:])
}
func (e ExtraZip64) DiskNumber() uint32 {
	if len(e) < 28 {
		return 0
	}
	return binary.LittleEndian.Uint32(e[24:])
}

const (
	AESCryptoVersionAE1 = 0x0001 //AE-1
	AESCryptoVersionAE2 = 0x0002 //AE-2

	AESCryptoEncryptionStrengthAES128 = 0x01 //AES-128
	AESCryptoEncryptionStrengthAES192 = 0x02 //AES-192
	AESCryptoEncryptionStrengthAES256 = 0x03 //AES-256

)

// ExtraAESCrypto struct
// +---------------------+-----------------------+
// | 字段                | 长度（字节）          |
// +---------------------+-----------------------+
// | Version             | 2 (AE-1/AE-2)         |
// | Vendor ID           | 2 ("AE")              |
// | Encryption Strength | 1 (1=AES128, 2=192, 3=256) |
// | Compression Method  | 2 (如 8=Deflate)      |
// +---------------------+-----------------------+
type ExtraAESCrypto []byte

func (e ExtraAESCrypto) Version() uint16           { return binary.LittleEndian.Uint16(e) }
func (e ExtraAESCrypto) VendorID() uint16          { return binary.LittleEndian.Uint16(e[2:]) }
func (e ExtraAESCrypto) EncryptionStrength() uint8 { return e[4] }
func (e ExtraAESCrypto) CompressionMethod() uint16 { return binary.LittleEndian.Uint16(e[5:]) }

func AESCryptoExtraField() []byte {
	buf := make([]byte, 11)
	binary.LittleEndian.PutUint16(buf[:2], ExtraHeaderAESCrypto)
	binary.LittleEndian.PutUint16(buf[2:4], 7)
	binary.LittleEndian.PutUint16(buf[4:6], AESCryptoVersionAE2)
	buf[6], buf[7] = 'A', 'E'
	buf[8] = AESCryptoEncryptionStrengthAES256

	binary.LittleEndian.PutUint16(buf[9:11], CompressMethodDeflate)
	return buf[:]
}

type FieldZip64 []byte

type ExtraField []byte

func (f ExtraField) HeaderID() uint16 {
	return binary.LittleEndian.Uint16(f)
}

func (f ExtraField) DataSize() uint16 {
	return binary.LittleEndian.Uint16(f[2:])
}
func (f ExtraField) Data() []byte {
	return f[4:]
}

type ExtraFields []byte

func (e ExtraFields) Fields() ([]ExtraField, error) {
	var fields []ExtraField
	for len(e) > 4 {
		end := binary.LittleEndian.Uint16(e[2:]) + 4
		if uint16(len(e)) < end {
			return nil, fmt.Errorf("invalid zip extra fields")
		}
		fields = append(fields, ExtraField(e[:end]))
		e = e[end:]
	}
	return fields, nil
}

func FindExtraField(fs []ExtraField, headerID uint16) ExtraField {
	for _, f := range fs {
		if f.HeaderID() == headerID {
			return f
		}
	}
	return nil
}

func FindAESCryptoExtraField(fs []ExtraField) ExtraAESCrypto {
	d := FindExtraField(fs, ExtraHeaderAESCrypto)
	if d == nil {
		return nil
	}
	return d.Data()
}
