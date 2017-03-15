package multisum

import (
	"bytes"
	"io"
	"testing"
)

func Test001(T *testing.T) {

	hash4m1b := map[string]string{
		"\"md5\"":      "ee7f09a6bf677959bb4a7ff4a5de5ff6",
		"\"sha1\"":     "92923fdc11c05c915843b8f9464bce08b9f2f2cd",
		"\"sha256\"":   "9944346590d3e9ca3668a07facd9217cfabb14f5eeb8da6d7dc8342b7ef56cc2",
		"\"sha512\"":   "7dc7a55540a0891b9fd7dde167eb48ee6cbdc89ddc6a9a9dffc1eb7d5c35bf849a59fdd669b2dd8824c17a0c64eecb33e665650ed7ff078c13f8b708a797357a",
		"\"sha3-256\"": "0095A7DBFC277D55642D61DA80542E59DC29CFC59028194D26925AE97AB7A185",
		"\"sha3-512\"": "40152F921CF51496667A0040EF6D710EE35228535E70228845417FF742569BD44F83F69297C642F3896DAA9DB8405C1AFF839BBB6C6CA435A7CC5E47EEFAB8D9",

		"\"sha1segs\"": "\n\"e41d6d3b4ca21efdd7e24dbe5850c254caac8cce\",\"e41d6d3b4ca21efdd7e24dbe5850c254caac8cce\",\"e41d6d3b4ca21efdd7e24dbe5850c254caac8cce\",\"e41d6d3b4ca21efdd7e24dbe5850c254caac8cce\",\"c78ebd3c85a39a596d9f5cfd2b8d240bc1b9c125\"",

		"\"md5segs\"": "\n\"769f946758f0d2c1f6e7941c5ad373ae\",\"769f946758f0d2c1f6e7941c5ad373ae\",\"769f946758f0d2c1f6e7941c5ad373ae\",\"769f946758f0d2c1f6e7941c5ad373ae\",\"8d39dd7eef115ea6975446ef4082951f\"",
	}

	hashtrunc := map[string]string{
		"md5-1a":  "752b8a6b31799dc5b3264acc1ce32128",
		"sha1-1a": "2bc1acc8273e727d194ba79226da32543b4a45db",
		"md5-1b":  "39e69bc3d445ca46719a77e05220eb66",
		"sha1-1b": "944c8b76bf30bb2108a3cb2f1f4662d867ce7b01",
	}

	// Byte Source, ByteS, Byte Start, Byte Scratch(space), Buffer Something?
	bs := make([]byte, 1024*4096+1)
	bs[0] = byte(128)
	for ii := 1; ii < 256; ii++ {
		bs[ii] = byte(ii)
	}
	copy(bs[256:], bs[0:256])
	copy(bs[512:], bs[0:256])
	copy(bs[768:], bs[0:256])
	bsp := 1024
	for ii := 1; ii < 4096; ii++ {
		bsp += copy(bs[bsp:], bs[0:1024])
	}
	copy(bs[bsp:], bs[0:1])

	br := bytes.NewReader(bs)
	lr := io.LimitReader(br, 1024*4096+1)
	sumFull := SumReader(br, 1024*1024)

	br.Seek(0, 0) // reader to start, from start
	lr = io.LimitReader(br, 1024*4096+1)
	sumShort := SumReader(lr, 1024*1024-1)

	CompareRes := func(l string, r string) int {
		return bytes.Compare(bytes.ToLower([]byte(l)), bytes.ToLower([]byte(r[1:len(r)-1])))
	}
	CompareRaw := func(l string, r []byte) int {
		return bytes.Compare(bytes.ToLower([]byte(l)), bytes.ToLower(r))
	}

	for _, rawHash := range bytes.Split(sumFull, []byte(",\n")) {
		tmp := bytes.Split(rawHash[1:], []byte(":"))
		k, v := string(tmp[0]), string(tmp[1])
		if 0 != CompareRes(hash4m1b[k], v) {
			T.Errorf("%s\t\nexpected:\n\t%s\ngot:\n\t%s\n", k, hash4m1b[k], v)
		}
	}

	for _, rawHash := range bytes.Split(sumShort, []byte(",\n")) {
		tmp := bytes.Split(rawHash[1:], []byte(":"))
		k, v := tmp[0], tmp[1]
		switch {
		case 0 == bytes.Compare(k, []byte("\"md5segs\"")):
			segHash := bytes.Split(v[3:], []byte("\",\""))
			if 0 != CompareRaw(hashtrunc["md5-1a"], segHash[0]) ||
				0 != CompareRaw(hashtrunc["md5-1b"], segHash[1]) {
				T.Errorf("\nFailed short seg MD5\n")
			}
		case 0 == bytes.Compare(k, []byte("\"sha1segs\"")):
			segHash := bytes.Split(v[3:], []byte("\",\""))
			if 0 != CompareRaw(hashtrunc["sha1-1a"], segHash[0]) ||
				0 != CompareRaw(hashtrunc["sha1-1b"], segHash[1]) {
				T.Errorf("\nFailed short seg SHA1\n")
			}
		}
	}
}
