# github.com/chux0r/filemage
   
Filemage is a utility package written in Go that helps validate files. 
1) No-choke limit! Samples 1st 100 bytes of file only. 
2) Uses file magic signatures to attempt identification  
3) Scans for UTF-8 to determine text or binary
    
## FileMagicEval
Tickles an input file header's file magic to determine what the filetype _really_ is, regardless of context or extension.   
   
## IsThisUtf8 
Input a byte slice and get back the answer, the byte length of the utf-8 encoded stuff, and any utf-8 text as a string (binary stripped)   
   
## HttpFileHeadMagicCheck
Input a URL and get back the filetype, if it can be determined ("" returned if it cannot.)
*NOTE: File read limits to 1st 100 bytes*   
    
**AUTHOR: Chuck Geigner a.k.a. "mongoose", a.k.a. "chux0r"**  
**DATE:   13NOV2023**  
   
*Copyright © 2023 CT Geigner, All rights reserved*
*Free to use under GNU GPL v2, see https://github/chux0r/filemage/LICENSE.md*
   
Written for use with QR Sentry security steps and file validation, but probably plenty useful for other stuff.
   
*--ctg 24NOV2023*
   


