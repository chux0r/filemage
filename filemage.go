/******************************************************************************
* filemage.go
*
* Go program tickles an input file's file magic to determine in a real way what
* the filetype _really_ is, regardless of context or extension.
*
* INPUT:        Any file reference on the internet (NOT "the file")
*
* PROCESSING:   Stream file. Sample first N bytes to get file magic and
*               sample for file encoding analysis
*				Eval BIN or TEXT
*               [BIN] Compare to known magic
*				[TXT] Analyze text sample to determine type
*
* OUTPUT:		Return Mode[BIN/TXT]; int type if known (0 for unkn); Eval
*               results [EXE|COM|INFO|UNKN]; Sample head if unkn
*
* EXCEPTIONS	oversize files.
*
* AUTHOR: Chuck Geigner a.k.a. "mongoose", a.k.a. "chux0r"
* DATE:   13NOV2023
*
******************************************************************************/
package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"unicode/utf8"
)

type magic_t struct {
	filemode string // "binary" or "text"
	filetype string // "ex: MPEG4"
	content  string // "executable", "metadata", "rawdata", "consumable", "packedmulti", "image"
	magic    string // "file magic, convertable to []byte"
}

func main() {
	// Ultimately want to be a function that takes a URL string input and returns the 4 fields of the magic_t struct
	buf := make([]byte, 100) // We only need the first 100 bytes to do type and magic validation checks
	//respData, err := http.Get("http://chux0r.org/images/chux-n-nin.jpg") // grab a session, response, metadata, file data, etc JPG, test ok
	//respData, err := http.Get("https://filesamples.com/samples/video/mpg/sample_1280x720_surfing_with_audio.mpg") //MPG, test ok
	//respData, err := http.Get("http://chux0r.org/images/banner-main4.png") //PNG, test ok
	respData, err := http.Get("https://slashdot.org")
	readErrChk(err)
	fmt.Println("++ RESPONSE STRUCT RAW ++\n\n", respData, "\n\n++ FILE SERVED ++\n")
	// NOTE: according to the http.Get docs, the response body is streamed on demand as the Body field is read. So,
	// if we limit the read, we avoid overhead of downloading large files
	lrReader := &io.LimitedReader{R: respData.Body, N: 100} // create a Reader that reads only the 1st 100 bytes of the file
	buf, err = io.ReadAll(lrReader)                         // use the LimitedReader to fill our little buffer w the 1st 100 bytes
	readErrChk(err)
	//fmt.Println(string(buf))
	fmt.Printf("%x", buf)
	//io.Copy(os.Stdout, respData.Body)
	fileType := evalHeader(buf)
	fmt.Printf("\nFiletype detected: %s\tMagic: % x\n", fileType.filetype, fileType.magic)

}

func isThisUtf8(h []byte) (bool, int, string) {
	// use utf8.ValidRune on each header element to eval. Count the number of valid utf8 to determine. If YES, send the string back
	count := 0
	var b = strings.Builder{}
	for _, c := range string(h) {
		if utf8.ValidRune(c) {
			count++
			b.WriteRune(c)
		}
	}
	if len(b.String()) > 40 {
		return true, b.Len(), b.String()
	} else {
		return false, b.Len(), b.String()
	}
}

func evalHeader(h []byte) magic_t {
	var magictable = []magic_t{
		{filemode: "text", filetype: "XML", content: "metadata", magic: "\x00\x00\x00\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20"},
		{filemode: "bin", filetype: "Video mpeg .mpg", content: "consumable", magic: "\x00\x00\x01\xBA"},
		{filemode: "bin", filetype: "Video mpeg .mpg", content: "consumable", magic: "\x00\x00\x01\xB3"},
		{filemode: "text", filetype: "XML", content: "metadata", magic: "\x00\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20"},
		{filemode: "bin", filetype: "Web Assembly wasm", content: "executable", magic: "\x00\x61\x73\x6D"},
		{filemode: "bin", filetype: "Keepass .kdbx", content: "consumable", magic: "\x03\xD9\xA2\x9A\x67\xFB\x4B\xB5"},
		{filemode: "bin", filetype: "MS EXCEL .xls", content: "consumable", magic: "\x09\x08\x10\x00\x00\x06\x05\x00"},
		{filemode: "bin", filetype: "MKV/WEBM Video .webm`", content: "consumable", magic: "\x1A\x45\xDF\xA3"},
		{filemode: "bin", filetype: "Lua bytecode", content: "executable", magic: "\x1B\x4C\x75\x61"},
		{filemode: "bin", filetype: "GZIP/TGZ Compressed Archive .gz .tgz", content: "packedmulti", magic: "\x1F\x8B"},
		{filemode: "bin", filetype: ".Z Zip", content: "packedmulti", magic: "\x1F\x9D"},
		{filemode: "bin", filetype: "TarZ Zipped tarball", content: "packedmulti", magic: "\x1F\xA0"},
		{filemode: "bin", filetype: "MS Outlook", content: "consumable", magic: "\x21\x42\x44\x4E"},
		{filemode: "bin", filetype: "VMDK VMware 4 Virtual Disk description", content: "image", magic: "\x23\x20\x44\x69\x73\x6B\x20\x44"},
		{filemode: "text", filetype: "#! She Bang shell executable", content: "executable", magic: "\x23\x21"},
		{filemode: "bin", filetype: "VBScript .vbs", content: "executable", magic: "\x23\x40\x7E\x5E"},
		{filemode: "bin", filetype: "postscript", content: "metadata", magic: "\x25\x21\x50\x53\x2D\x41\x64\x6F"},
		{filemode: "bin", filetype: "Adobe PDF .pdf", content: "packedmulti", magic: "\x25\x50\x44\x46"},
		{filemode: "text", filetype: "Encryption Keyfile", content: "metadata", magic: "\x2D\x2D\x2D\x2D\x2D\x42\x45\x47\x49\x4E\x20"},
		{filemode: "bin", filetype: "LZA compressed archive", content: "packedmulti", magic: "\x2D\x6C\x68"},
		{filemode: "bin", filetype: "Windows Media File .wma .wmv", content: "consumable", magic: "\x30\x26\xB2\x75\x8E\x66\xCF\x11"},
		{filemode: "bin", filetype: "CPIO archive .cpio", content: "packedmulti", magic: "\x30\x37\x30\x37\x30"},
		{filemode: "bin", filetype: "ISO disk image .iso", content: "image", magic: "\x33\xED"},
		{filemode: "bin", filetype: "7zip archive .7z", content: "packedmulti", magic: "\x37\x7A\xBC\xAF\x27\x1C"},
		{filemode: "bin", filetype: "Adobe Photoshop .psd", content: "consumable", magic: "\x38\x42\x50\x53"},
		{filemode: "text", filetype: "XML", content: "metadata", magic: "\x3C\x00\x3F\x00\x78\x00\x6D\x00\x6C\x00\x20"},
		{filemode: "text", filetype: "XML", content: "metadata", magic: "\x3C\x00\x00\x00\x3F\x00\x00\x00\x78\x00\x00\x00\x6D\x00\x00\x00\x6C\x00\x00\x00\x20\x00\x00\x00"},
		{filemode: "bin", filetype: "VirtualBox VDI", content: "image", magic: "\x3C\x3C\x3C\x20\x4F\x72\x61\x63\x6C\x65\x20\x56\x4D\x20\x56\x69\x72\x74\x75\x61\x6C\x42\x6F\x78\x20\x44\x69\x73\x6B\x20\x49\x6D\x61\x67\x65\x20\x3E\x3E\x3E"},
		{filemode: "bin", filetype: "Roblox game", content: "consumable", magic: "\x3C\x72\x6F\x62\x6C\x6F\x78\x21"},
		{filemode: "bin", filetype: "LLVM bytecode", content: "executable", magic: "\x42\x43"},
		{filemode: "bin", filetype: "Bitmap image .bmp", content: "consumable", magic: "\x42\x4D"},
		{filemode: "bin", filetype: "VMWare3 VMDK", content: "image", magic: "\x43\x4F\x57\x44"},
		{filemode: "bin", filetype: "Adobe Flash .swf", content: "executable", magic: "\x43\x57\x53"},
		{filemode: "bin", filetype: "Windows PE", content: "executable", magic: "\x45\x50\x00\x00"},
		{filemode: "bin", filetype: "GIF image .gif", content: "consumable", magic: "\x47\x49\x46\x38\x37\x61"},
		{filemode: "bin", filetype: "GIF image, animated .gif", content: "consumable", magic: "\x47\x49\x46\x38\x39\x61"},
		{filemode: "bin", filetype: "Installshield CAB .cab", content: "packedmulti", magic: "\x49\x53\x63\x28"},
		{filemode: "bin", filetype: "Compressed ISO", content: "image", magic: "\x49\x73\x5A\x21"},
		{filemode: "bin", filetype: "PPC executable", content: "executable", magic: "\x4A\x6F\x79\x21"},
		{filemode: "bin", filetype: "VMWare VMDK", content: "image", magic: "\x4B\x44\x4D"},
		{filemode: "text", filetype: "XML", content: "metadata", magic: "\x4C\x6F\xA7\x94\x93\x40"},
		{filemode: "bin", filetype: "DOS/Win .exe", content: "executable", magic: "\x4d\x5a"},
		{filemode: "bin", filetype: "OGG Vorbis music .ogg", content: "consumable", magic: "\x4F\x67\x67\x53"},
		{filemode: "bin", filetype: "Zipped MS Office Content .docx .xlsx .pptx .docm", content: "packedmulti", magic: "\x50\x4B\x03\x04"},
		{filemode: "bin", filetype: "RAR .rar", content: "packedmulti", magic: "\x52\x61\x72\x21\x1A\x07"},
		{filemode: "bin", filetype: "Encapsulated postscript .eps", content: "metadata", magic: "\x62\x65\x2D"},
		{filemode: "bin", filetype: "MS Virtual PC Disk .vhd", content: "image", magic: "\x63\x6F\x6E\x6E\x65\x63\x74\x69\x78"},
		{filemode: "bin", filetype: "MS Virtual PC Disk .vhdx", content: "image", magic: "\x76\x68\x64\x78\x66\x69\x6C\x65"},
		{filemode: "bin", filetype: "ELF Linux executable", content: "executable", magic: "\x7F\x45\x4C\x46"},
		{filemode: "bin", filetype: "PNG image .png", content: "consumable", magic: "\x89\x50\x4E\x47"},
		{filemode: "bin", filetype: "WMV video .wmv", content: "able", magic: "\xA6\xD9\x00\xAA\x00\x62\xCE\x6C"},
		{filemode: "bin", filetype: "Java bytecode", content: "executable", magic: "\xca\xfe\xba\xbe"},
		{filemode: "bin", filetype: "Packed Java bytecode", content: "executable", magic: "\xCA\xFE\xD0\x0D"},
		{filemode: "bin", filetype: "MS Word docfile .doc", content: "consumable", magic: "\xD0\xCF\x11\xE0"},
		{filemode: "text", filetype: "Win UTF-8 encoded text", content: "consumable", magic: "\xEF\xBB\xBF"},
		{filemode: "bin", filetype: "XZ compressed image .xz", content: "image", magic: "\xFD\x37\x7A\x58\x5A"},
		{filemode: "text", filetype: "Little endian UTF-16 encoded text", content: "executable", magic: "\xFF\xFE"},
		{filemode: "bin", filetype: "JPEG image .jpg", content: "consumable", magic: "\xFF\xD8\xFF\xE0"},
	}
	for _, magicType := range magictable {
		// chop length of header slice to the current file magic compare to enable a bytes.Equal check
		if bytes.Equal(h[:len(magicType.magic)], []byte(magicType.magic)) {
			return magicType
		}
	}
	// no file magic hits? do a UTF-8 scan on the header, display what's discovered, and return "unknown"
	textY, n, tx := isThisUtf8(h)
	fmt.Printf("\nFile has %d%% UTF-8 text content.\nText: %s\n", n, tx)
	if textY {
		return magic_t{filemode: "text", filetype: "unknown", content: "unknown", magic: ""}
	} else {
		return magic_t{filemode: "bin", filetype: "unknown", content: "unknown", magic: ""}
	}
}

func readErrChk(e error) {
	if e != nil {
		fmt.Print(e, "\nExiting (Error code 1).")
		os.Exit(1)
	}
}

/*  ---------- Data map of HTTP/S response fields ------------
&
{
200 OK				}Response.Status
200 				}Response.StatusCode
HTTP/1.1  			}Response.Proto
1  					}Response.ProtoMajor
1  					}Response.ProtoMinor
	map[ 			}Response.Header
		Cache-Control:[public]
		Content-Type:[application/javascript; charset=utf-8]
		Date:[Thu, 16 Nov 2023 19:33:37 GMT]
		Expires:[Thu, 16 Nov 2023 20:03:37 GMT]
		Referrer-Policy:[origin-when-cross-origin]
		Set-Cookie:[
			_hash=c51935bb-314a-4f09-8e36-e749ca81f0dd;
			path=/; secure; HttpOnly; SameSite=None
			_hash=c51935bb-314a-4f09-8e36-e749ca81f0dd;
			expires=Thu, 16-Nov-2028 05:00:00 GMT;
			path=/; secure; HttpOnly; SameSite=None
			_hashV=202311/1; path=/; secure; HttpOnly; SameSite=None
			_hashV=202311/1; expires=Thu, 16-Nov-2028 05:00:00 GMT;
			path=/; secure; HttpOnly; SameSite=None
			_node=536873482.47873.0000; path=/; Httponly;
			Secure TS01e84c7d=01370406faf786060864a05b9ded7a3cbd06f4843fb62afcbe07bd6edc338a77af974a592ea11c41a16b223125a463b4fbece42ddd;
			Path=/; HTTPOnly]
		Strict-Transport-Security:[max-age=31536000]
		]
	0xc0001a0040  	}Response.Body (ptr)
	-1  			}Response.ContentLength
	[]  			}Response.TransferEncoding
	false  			}Response.Close
	true  			}Response.Uncompressed
	map[]  			}Response.Trailer
	0xc00013a000 	}Response.Request (ptr)
	0xc0000f2000 	}Response.TLS (ptr)
}
*/
