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
	"fmt"
	"io"
	"net/http"
	"os"
)



func main() {
	buf := make([]byte, 100) // limit file magic check to first 100 bytes
	respData, err := http.Get("http://chux0r.org/images/chux-n-nin.jpg") // grab a session, response, metadata, file data, etc
	readErrChk(err)
	fmt.Println("++ RESPONSE STRUCT RAW ++\n\n",respData,"\n\n++ FILE SERVED ++\n")
	//dlfile.Body.Read(buf)
	//fmt.Printf("%s\n",string(buf))
	
	//lrBuf := &io.LimitedReader(R: repData.Body.Read(buf), N: 100)
	lrBuf := &io.LimitedReader{R: respData.Body, N: 100}
	buf, err = io.ReadAll(lrBuf)
	readErrChk(err) 
	fmt.Println(string(buf))
	//io.Copy(os.Stdout, respData.Body)
}

func readErrChk (e error) {
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

/* FILE MAGIC LOOKUP
1F 8B						GZIP, TGZ
1F 9D						Z
1F A0						TAR.Z
75 73 74 61 72				TAR
50 4B 03 04					PKZIP/ZIP/XLSX/DOCX/PPTX/VSDX/DOCM
23 40 7E 5E					VBSCRIPT
25 50 44 46					PDF
2D 6C 68					LZA compressed archive
37 7A BC AF 27 1C			7zip
FD 37 7A 58 5A				XZ compressed image

43 57 53					SWF
52 61 72 21 1A 07	 		RAR
4d 5a						MZ WIN EXE
7F 45 4C 46					ELF
23 21						#! plaintext executable
D0 CF 11 E0 A1 B1 1A E1		MS Doc/Pot/MSI

1A 45 DF A3					MKV/WebM
09 08 10 00 00 06 05 00		MS Excel
00 00 01 B?					MPEG
21 42 44 4E					MS Outlook


23 20 44 69 73 6B 20 44
65 73 63 72 69 70 74 6F		VMWare4 VMDK
43 4F 57 44					VMWare3 VMDK

25 21 50 53 2D 41 64 6F		
62 65 2D					postscript/EPS

30 26 B2 75 8E 66 CF 11
A6 D9 00 AA 00 62 CE 6C		WMV

30 37 30 37 30 3(127)		cpio archive
42 4D						BMP
FF D8 FF E0					JPG		Also poss. in there: JFIF ExifII
89 50 4E 47					PNG
47 49 46 38 39 61			GIF, animated
47 49 46 38 37 61			GIF


03 D9 A2 9A 67 FB 4B B5		KDBX
4F 67 67 53					OGG Vorbis
33 ED						ISO image
*/