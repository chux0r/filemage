package filemage

/******************************************************************************
* filemage_test.go
*
* AUTHOR: Chuck Geigner a.k.a. "mongoose", a.k.a. "chux0r"
* DATE:   24NOV2023
*
* Copyright © 2023 CT Geigner, All rights reserved
* Free to use under GNU GPL v2, see https://github/chux0r/filemage/LICENSE.md
******************************************************************************/

import (
	"testing"
)

func TestHttpFileHeadMagicCheck(t *testing.T) {
	htr := "https://filesamples.com/samples/video/mpg/sample_1280x720_surfing_with_audio.mpg"
	expected := "Video mpeg .mpg"
	if rtn := HttpFileHeadMagicCheck(htr); rtn != expected {
		t.Errorf("HttpFileHeadMagicCheck(%s) failed. Returned \"%s\"; Expected \"%s\"", htr, rtn, expected)
	}
}

func TestIsThisUtf8(t *testing.T) {
	utfTestString := "ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ᛫ᛋᚳᛖᚪᛚ᛫ᚦᛖᚪᚻ᛫ᛗᚪᚾᚾᚪ᛫ᚷᛖᚻᚹᛦᛚᚳ᛫ᛗᛁᚳᛚᚢᚾ᛫ᚻᛦᛏ᛫ᛞᚫᛚᚪᚾ᛫ᚷᛁᚠ᛫ᚻᛖ᛫ᚹᛁᛚᛖ᛫ᚠᚩᚱ᛫ᛞᚱᛁᚻᛏᚾᛖ᛫ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ᛬"
	expctCt := 327
	b, i, s := IsThisUtf8([]byte(utfTestString))
	if (!b) || (i != expctCt) || (s != "ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ᛫ᛋᚳᛖᚪᛚ᛫ᚦᛖᚪᚻ᛫ᛗᚪᚾᚾᚪ᛫ᚷᛖᚻᚹᛦᛚᚳ᛫ᛗᛁᚳᛚᚢᚾ᛫ᚻᛦᛏ᛫ᛞᚫᛚᚪᚾ᛫ᚷᛁᚠ᛫ᚻᛖ᛫ᚹᛁᛚᛖ᛫ᚠᚩᚱ᛫ᛞᚱᛁᚻᛏᚾᛖ᛫ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ᛬") {
		t.Errorf("IsThisUtf8() Something failed. \nUTF8 check should be \"%t\", got \"%t\".\nData length should be %d bytes, got %d bytes.\n String return should be: \n\"%s\"\nGot:\n\"%s\"", true, b, expctCt, i, utfTestString, s)
	}
}
