/******************************************************************************
* filemage.go
*
* Go program tickles an input file's file magic to determine in a real way what
* the filetype _really_ is, regardless of context or extension.
*
* AUTHOR: CT Geigner "mongoose"
* DATE:   13NOV2023
*
******************************************************************************/
package main

func main() {
	bs, err := ReadFile
