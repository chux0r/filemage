```

Program- take a memory dump and isolate all files by file magic headers   
statistical analysis on plaintext to determine plaintext   

Program- interrogate/fuzz API tool. Cheap parlor tricks. Dirty pool. Bad behavior. All inbounds.   

of interest   
purpose:   
	ID: ALL   
	BAD?: SOME   
	  
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
FF D8 FF E0					JPG
89 50 4E 47					PNG
47 49 46 38 39 61			GIF, animated
47 49 46 38 37 61			GIF


03 D9 A2 9A 67 FB 4B B5		KDBX
4F 67 67 53					OGG Vorbis
33 ED						ISO image


????
01 00
00 02
00 00 03 00 00 04 00 00		DAT file

```

