package ezip

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtraFields(t *testing.T) {
	extraData, _ := base64.StdEncoding.DecodeString("CgAgAAAAAAABABgAhYCkdH3q2wEAAAAAAAAAAAAAAAAAAAAAAZkHAAIAQUUDCAA=")
	extra := ExtraFields(extraData)
	fs, err := extra.Fields()
	require.NoError(t, err)
	require.Len(t, fs, 2)
	var s int
	for _, f := range fs {
		s += len(f)
		switch f.HeaderID() {
		case ExtraHeaderAESCrypto:
			data := ExtraAESCrypto(f.Data())
			t.Log(data.VendorID())
			t.Log(data.Version())
			t.Log(data.EncryptionStrength())
			t.Log(data.CompressionMethod())
		case ExtraHeaderNTFSInfo:
			data := ExtraNTFSInfo(f.Data())
			t.Log("ntfs atime:", FileTime(data.Atime()))
			t.Log("ntfs ctime:", FileTime(data.Ctime()))
			t.Log("ntfs mtime:", FileTime(data.Mtime()))
		default:
			assert.NotEmpty(t, f.HeaderID())
		}

	}
	require.Equal(t, s, len(extraData))
}
