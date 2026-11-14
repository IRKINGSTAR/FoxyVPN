// gen_ico converts assets/icon.png into a Windows .ico (PNG-compressed entry).
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image/png"
	"os"
)

func main() {
	raw, err := os.ReadFile("assets/icon.png")
	if err != nil {
		panic(err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		panic(err)
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w > 255 || h > 255 {
		panic("icon too large for a single ICO entry")
	}
	var buf bytes.Buffer
	// ICONDIR
	buf.Write([]byte{0, 0})       // reserved
	buf.Write([]byte{1, 0})       // type: icon
	buf.Write([]byte{1, 0})       // count: 1
	// ICONDIRENTRY
	buf.WriteByte(byte(w % 256))  // width
	buf.WriteByte(byte(h % 256))  // height
	buf.WriteByte(0)              // palette
	buf.WriteByte(0)              // reserved
	binary.Write(&buf, binary.LittleEndian, uint16(1))  // planes
	binary.Write(&buf, binary.LittleEndian, uint16(32)) // bpp
	binary.Write(&buf, binary.LittleEndian, uint32(len(raw))) // size
	binary.Write(&buf, binary.LittleEndian, uint32(22))       // offset (6+16)
	buf.Write(raw)
	if err := os.WriteFile("assets/icon.ico", buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Println("assets/icon.ico written:", buf.Len(), "bytes,", w, "x", h)
}
