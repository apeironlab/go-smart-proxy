package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"runtime"
)

// trayIcon returns the tray icon bytes: PNG on macOS/Linux, ICO (wrapping a PNG) on Windows.
func trayIcon() []byte {
	const size = 32
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	bg := color.NRGBA{R: 0x22, G: 0x8B, B: 0xE6, A: 0xFF}
	fg := color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
	c := float64(size-1) / 2
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			if math.Hypot(float64(x)-c, float64(y)-c) <= float64(size)/2-1 {
				img.SetNRGBA(x, y, bg)
			}
		}
	}
	// right-pointing arrow: shaft + head
	for y := 14; y <= 17; y++ {
		for x := 7; x <= 20; x++ {
			img.SetNRGBA(x, y, fg)
		}
	}
	for i := 0; i <= 7; i++ {
		for y := 15 - i; y <= 16+i; y++ {
			img.SetNRGBA(17+(7-i), y, fg)
		}
	}

	var pngBuf bytes.Buffer
	if err := png.Encode(&pngBuf, img); err != nil {
		return nil
	}
	if runtime.GOOS != "windows" {
		return pngBuf.Bytes()
	}

	var ico bytes.Buffer
	binary.Write(&ico, binary.LittleEndian, []uint16{0, 1, 1})
	ico.Write([]byte{size, size, 0, 0})
	binary.Write(&ico, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&ico, binary.LittleEndian, uint32(pngBuf.Len()))
	binary.Write(&ico, binary.LittleEndian, uint32(22))
	ico.Write(pngBuf.Bytes())
	return ico.Bytes()
}
