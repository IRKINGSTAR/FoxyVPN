// gen_icon generates assets/icon.png (a simple FoxVPN badge) once.
package main

import (
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"
)

func main() {
	const size = 64
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	bg := color.RGBA{245, 130, 48, 255}  // fox orange
	dark := color.RGBA{30, 30, 36, 255}  // power symbol
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x-32) / 30.0
			dy := float64(y-32) / 30.0
			d := math.Sqrt(dx*dx + dy*dy)
			switch {
			case d <= 1.0:
				img.Set(x, y, bg)
			case d <= 1.08:
				img.Set(x, y, color.RGBA{200, 100, 30, 255}) // ring
			}
		}
	}
	// power ring (stroke)
	cx, cy := 32.0, 32.0
	rr := 13.0
	for a := -220.0; a <= 40.0; a += 0.25 {
		for w := 0.0; w < 3.2; w += 0.5 {
			x := int(cx + (rr+w)*math.Cos(a*math.Pi/180))
			y := int(cy + (rr+w)*math.Sin(a*math.Pi/180))
			if x >= 0 && y >= 0 && x < size && y < size {
				img.Set(x, y, dark)
			}
		}
	}
	// vertical line of the power symbol
	for y := 12; y <= 26; y++ {
		for w := 0.0; w < 3.2; w += 0.5 {
			img.Set(int(32+w), y, dark)
		}
	}
	out := filepath.Join("assets", "icon.png")
	_ = os.MkdirAll("assets", 0o755)
	f, err := os.Create(out)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if err := png.Encode(f, img); err != nil {
		panic(err)
	}
}
