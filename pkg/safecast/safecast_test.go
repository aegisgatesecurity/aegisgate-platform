// SPDX-License-Identifier: Apache-2.0

package safecast

import (
	"math"
	"testing"
)

func TestInt32_NormalValues(t *testing.T) {
	cases := []struct {
		input int
		want  int32
	}{
		{0, 0},
		{1, 1},
		{-1, -1},
		{100, 100},
		{-100, -100},
		{math.MaxInt32, math.MaxInt32},
		{math.MinInt32, math.MinInt32},
	}
	for _, c := range cases {
		got := Int32(c.input)
		if got != c.want {
			t.Errorf("Int32(%d) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestInt32_Overflow(t *testing.T) {
	if got := Int32(math.MaxInt32 + 1); got != math.MaxInt32 {
		t.Errorf("Int32(MaxInt32+1) = %d, want %d", got, math.MaxInt32)
	}
	if got := Int32(math.MaxInt); got != math.MaxInt32 {
		t.Errorf("Int32(MaxInt) = %d, want %d", got, math.MaxInt32)
	}
}

func TestInt32_Underflow(t *testing.T) {
	if got := Int32(math.MinInt32 - 1); got != math.MinInt32 {
		t.Errorf("Int32(MinInt32-1) = %d, want %d", got, math.MinInt32)
	}
	if got := Int32(math.MinInt); got != math.MinInt32 {
		t.Errorf("Int32(MinInt) = %d, want %d", got, math.MinInt32)
	}
}

func TestByte_NormalValues(t *testing.T) {
	cases := []struct {
		input int64
		want  byte
	}{
		{0, 0},
		{1, 1},
		{127, 127},
		{255, 255},
		{128, 128},
	}
	for _, c := range cases {
		got := Byte(c.input)
		if got != c.want {
			t.Errorf("Byte(%d) = %d, want %d", c.input, got, c.want)
		}
	}
}

func TestByte_OutOfRange(t *testing.T) {
	if got := Byte(-1); got != 0 {
		t.Errorf("Byte(-1) = %d, want 0", got)
	}
	if got := Byte(-1000); got != 0 {
		t.Errorf("Byte(-1000) = %d, want 0", got)
	}
	if got := Byte(256); got != 255 {
		t.Errorf("Byte(256) = %d, want 255", got)
	}
	if got := Byte(math.MaxInt64); got != 255 {
		t.Errorf("Byte(MaxInt64) = %d, want 255", got)
	}
}
