// Native DPAPI (CryptProtectData/CryptUnprotectData) via crypt32.dll.
package storage

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32           = windows.NewLazySystemDLL("crypt32.dll")
	procProtectData   = crypt32.NewProc("CryptProtectData")
	procUnprotectData = crypt32.NewProc("CryptUnprotectData")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

const cRYPTPROTECT_UI_FORBIDDEN = 0x1

// dpapiProtect encrypts data scoped to the current Windows user.
func dpapiProtect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("dpapi: empty input")
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob
	r, _, err := procProtectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0,                // szDataDescr
		0,                // pOptionalEntropy
		0,                // pvReserved
		0,                // pPromptStruct
		cRYPTPROTECT_UI_FORBIDDEN,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptProtectData: %v", err)
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(out.pbData))
	buf := make([]byte, out.cbData)
	copy(buf, unsafe.Slice(out.pbData, out.cbData))
	return buf, nil
}

// dpapiUnprotect decrypts user-scoped DPAPI data.
func dpapiUnprotect(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("dpapi: empty input")
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob
	r, _, err := procUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, // ppszDataDescr
		0, // pOptionalEntropy
		0, // pvReserved
		0, // pPromptStruct
		cRYPTPROTECT_UI_FORBIDDEN,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %v", err)
	}
	defer windows.CoTaskMemFree(unsafe.Pointer(out.pbData))
	buf := make([]byte, out.cbData)
	copy(buf, unsafe.Slice(out.pbData, out.cbData))
	return buf, nil
}
