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

/* FILE MAGIC LOOKUP, file beginning
00 00 00 3C 00 00 00 3F 00 00 00 78 00 00 00 6D 00 00 00 6C 00 00 00 20	XML
00 00 01 BA							MPEG
00 00 01 B3							MPEG
00 3C 00 3F 00 78 00 6D 00 6C 00 20	XML
00 61 73 6D							WASM, web assembly (EXE)
03 D9 A2 9A 67 FB 4B B5				KDBX
09 08 10 00 00 06 05 00				MS Excel
1A 45 DF A3							MKV/WebM
1B 4C 75 61							Lua Bytecode (EXE)
1F 8B								GZIP, TGZ (EXE)
1F 9D								Z (EXE)
1F A0								TAR.Z (EXE)
21 42 44 4E							MS Outlook
23 20 44 69 73 6B 20 44				VMware 4 Virtual Disk description file
23 21								#! plaintext executable
23 40 7E 5E							VBSCRIPT (EXE)
25 21 50 53 2D 41 64 6F				Postscript "%!"
25 50 44 46							PDF
2D 2D 2D 2D 2D 42 45 47 49 4E 20	Probable keyfile
2D 6C 68							LZA compressed archive
30 26 B2 75 8E 66 CF 11				Windows Media File .wma .wmv
30 37 30 37 30		 				cpio archive
33 ED								ISO image
37 7A BC AF 27 1C					7zip
38 42 50 53							Adobe Photoshop Document .psd
3C 00 3F 00 78 00 6D 00 6C 00 20 	XML
3C 00 00 00 3F 00 00 00 78 00 00 00 6D 00 00 00 6C 00 00 00 20 00 00 00	XML
3C 3C 3C 20 4F 72 61 63 6C 65 20 56 4D 20 56 69 72 74 75 61 6C 42 6F 78 20 44 69 73 6B 20 49 6D 61 67 65 20 3E 3E 3E	VirtualBox VDI
3C 72 6F 62 6C 6F 78 21				Roblox file
42 43								LLVM Bytecode
42 4D								BMP
43 4F 57 44							VMWare3 VMDK
43 57 53							SWF
45 50 00 00							WINDOWS PE EXE
47									MPEG (poss)
47 49 46 38 37 61					GIF
47 49 46 38 39 61					GIF, animated
49 53 63 28							Installshield CAB file (!)
49 73 5A 21							Compressed ISO
4A 6F 79 21							PPC EXE
4B 44 4D							VMDK
4C 6F A7 94 93 40					XML
4d 5a								MZ WIN EXE
4F 67 67 53							OGG Vorbis
50 4B 03 04							PKZIP/ZIP/XLSX/DOCX/PPTX/VSDX/DOCM
52 61 72 21 1A 07			 		RAR
62 65 2D							postscript/EPS
63 6F 6E 6E 65 63 74 69 78			MS Virtual PC VHD
76 68 64 78 66 69 6C 65				MS Virtual PC VHDX
7F 45 4C 46							ELF ("7FELF") (EXE)
89 50 4E 47							PNG
A6 D9 00 AA 00 62 CE 6C				WMV
CA FE BA BE							JAVA BYTECODE (EXE)
CA FE D0 0D							PACKED JAVA BYTECODE (EXE)
D0 CF 11 E0 						MS Doc/Pot/MSI
EF BB BF							Windows UTF-8 encoded text file
FD 37 7A 58 5A						XZ compressed image
FF FE								Little endian UTF-16 text file						
FF D8 FF E0							JPG		Also in there: "JFIF" OR "Exif"
?? ?? ?? ?? 66 74 79 70 69 73 6F 6D	ISO Base Media File (MPEG-4)
?? ?? ?? ?? 66 74 79 70 4D 53 4E 56	MPEG-4 video
========FILE END
55 5A						MBR end
FA DE DE AD					Apple Script end

========OTHER
OFFSET 257: 	75 73 74 61 72		TAR
OFFSET ??:		55 50 58 21			UPX-packed ELF EXE	
OFFSET 0x100:	45 50 00 00			WINDOWS PE EXE			
*/