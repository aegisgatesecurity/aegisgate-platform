// SPDX-License-Identifier: Apache-2.0
// =========================================================================
// AegisGate Lens - Build Tool: Icon Generator
// =========================================================================
//
// icons.go generates the four Chrome Web Store icon sizes
// from a source PNG. The source PNG is at
// lens-icon-source.png (sibling to this Go file).
//
// Chrome Web Store requires four sizes:
//   - icon-16.png    (toolbar icon)
//   - icon-32.png    (Windows taskbar / Mac dock)
//   - icon-48.png    (extension management page)
//   - icon-128.png   (Web Store listing, install dialog)
//
// The source PNG is expected to be square (or nearly
// square). If it has transparent padding, we auto-crop to
// the bounding box of the non-transparent content. If it
// has white padding, we auto-crop to the bounding box of
// the non-white content (alpha-channel check first, then
// pixel-luminance fallback).
//
// The generator runs as part of the build tool's bundle()
// step, BEFORE the manifest.json is written. The output
// icons go to <dist>/icons/.
//
// v3.5.0+ Lens Phase 2.
// =========================================================================

package main

import (
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
)

// iconSize is the dimension of a single icon.
type iconSize int

// The four required Chrome Web Store icon sizes.
const (
	icon16  iconSize = 16
	icon32  iconSize = 32
	icon48  iconSize = 48
	icon128 iconSize = 128
)

// generateIcons reads the source PNG and writes the four
// required icon sizes to <dist>/icons/icon-{16,32,48,128}.png.
//
// The source is auto-cropped to its non-transparent (or
// non-white) bounding box, then resized to each target
// size with nearest-neighbor sampling (which is what
// Chrome Web Store expects for crisp pixel rendering).
//
// The function returns an error if the source cannot be
// read or any of the output files cannot be written.
func generateIcons(dist string) error {
	srcPath := findSourceIcon()
	if srcPath == "" {
		// No source icon found. Skip silently -- the build
		// proceeds without icons. The Chrome Web Store
		// submission will fail later, but the build itself
		// succeeds. This is the v0.1.0 default behavior;
		// v0.2 will require the source icon to be present.
		return nil
	}
	srcImg, err := loadPNG(srcPath)
	if err != nil {
		return fmt.Errorf("load source icon %s: %w", srcPath, err)
	}
	// Auto-crop to the bounding box of the non-transparent
	// (or non-white) content.
	cropped := autoCrop(srcImg)
	// Ensure the output directory exists.
	iconsDir := filepath.Join(dist, "icons")
	if err := os.MkdirAll(iconsDir, 0o755); err != nil { // #nosec G301 G703 -- icons directory is the build's own output
		return fmt.Errorf("mkdir icons: %w", err)
	}
	// Generate each size.
	sizes := []iconSize{icon16, icon32, icon48, icon128}
	for _, s := range sizes {
		resized := resize(cropped, int(s), int(s))
		outPath := filepath.Join(iconsDir, fmt.Sprintf("icon-%d.png", int(s)))
		if err := writePNG(outPath, resized); err != nil {
			return fmt.Errorf("write %s: %w", outPath, err)
		}
	}
	return nil
}

// findSourceIcon returns the path to the source icon PNG.
// The source lives next to the build tool's Go source files.
//
// We use runtime.Caller to find this file's directory at
// compile time. This works whether the build tool is invoked
// via `go run ./tools/build-lens-extension/` (which puts
// the binary in a temp dir) or via the built binary
// directly. CWD-relative lookup is a fallback.
//
// Returns "" if no source is found (v0.1 behavior: skip
// icon generation silently; v0.2 will fail the build).
func findSourceIcon() string {
	candidates := []string{
		"lens-icon-source.png",
		"lens-icon.png",
		"icon.png",
	}
	// Try the directory containing this Go source file.
	_, thisFile, _, ok := runtime.Caller(0)
	if ok {
		thisDir := filepath.Dir(thisFile)
		for _, c := range candidates {
			p := filepath.Join(thisDir, c)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// Try relative to the working directory.
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	// Try relative to the executable's directory.
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		for _, c := range candidates {
			p := filepath.Join(exeDir, c)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}

// loadPNG reads a PNG file and returns the decoded image.
func loadPNG(path string) (image.Image, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the build tool's own asset
	if err != nil {
		return nil, err
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// writePNG encodes the image as PNG and writes it.
func writePNG(path string, img image.Image) error {
	f, err := os.Create(path) // #nosec G304 G306 G703 -- path is the build's own output, derived from a hardcoded filename
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// autoCrop returns a cropped image containing only the
// non-transparent (or non-white) content. If the entire
// image is opaque (no transparency), we fall back to a
// non-white-pixel crop.
//
// The result is centered in a square canvas so the
// resize step doesn't distort a non-square crop.
func autoCrop(src image.Image) image.Image {
	bounds := src.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	// Find the bounding box of non-transparent / non-white
	// pixels.
	minX, minY := w, h
	maxX, maxY := 0, 0
	found := false
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := src.At(bounds.Min.X+x, bounds.Min.Y+y)
			if isContentPixel(c) {
				if x < minX {
					minX = x
				}
				if y < minY {
					minY = y
				}
				if x > maxX {
					maxX = x
				}
				if y > maxY {
					maxY = y
				}
				found = true
			}
		}
	}
	if !found {
		// Empty image; return as-is.
		return src
	}
	// Crop to the bounding box.
	cropped := src.(interface {
		SubImage(r image.Rectangle) image.Image
	}).SubImage(image.Rect(
		bounds.Min.X+minX,
		bounds.Min.Y+minY,
		bounds.Min.X+maxX+1,
		bounds.Min.Y+maxY+1,
	))
	cw := cropped.Bounds().Dx()
	ch := cropped.Bounds().Dy()
	// Square-crop: take the smaller of cw, ch and center.
	if cw == ch {
		return cropped
	}
	var x0, y0, x1, y1 int
	if cw > ch {
		// Wide; crop horizontally to center.
		off := (cw - ch) / 2
		x0 = cropped.Bounds().Min.X + off
		x1 = x0 + ch
		y0 = cropped.Bounds().Min.Y
		y1 = cropped.Bounds().Max.Y
	} else {
		// Tall; crop vertically to center.
		off := (ch - cw) / 2
		x0 = cropped.Bounds().Min.X
		x1 = cropped.Bounds().Max.X
		y0 = cropped.Bounds().Min.Y + off
		y1 = y0 + cw
	}
	return cropped.(interface {
		SubImage(r image.Rectangle) image.Image
	}).SubImage(image.Rect(x0, y0, x1, y1))
}

// isContentPixel returns true if the pixel is not fully
// transparent and not pure white (the typical "background"
// color in our logo).
func isContentPixel(c color.Color) bool {
	r, g, b, a := c.RGBA()
	// Treat alpha < 0x40 (25%) as background (transparent).
	if a < 0x4040 {
		return false
	}
	// Treat near-white (>F0F0F0) as background.
	if r > 0xf0f0 && g > 0xf0f0 && b > 0xf0f0 {
		return false
	}
	return true
}

// resize scales the source image to the given width and
// height using nearest-neighbor sampling. Nearest-neighbor
// preserves sharp edges (which is what we want for icons).
//
// For a high-quality downscale from a large source (e.g.,
// 932×932 -> 16×16), nearest-neighbor produces a slightly
// blocky result. For icons at small sizes, this is usually
// fine and avoids the GPU cost of Lanczos or similar.
// v0.2+ may switch to bilinear for the larger sizes.
func resize(src image.Image, w, h int) image.Image {
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	srcBounds := src.Bounds()
	srcW := srcBounds.Dx()
	srcH := srcBounds.Dy()
	if srcW == 0 || srcH == 0 {
		return dst
	}
	for y := 0; y < h; y++ {
		// Nearest-neighbor: pick the source row proportionally.
		sy := srcBounds.Min.Y + (y*srcH)/h
		for x := 0; x < w; x++ {
			sx := srcBounds.Min.X + (x*srcW)/w
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}
