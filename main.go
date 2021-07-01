package main

import (
	"fmt"
	"os"
	"winFileData"
)

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: winFileDataSample pathToFile")
		os.Exit(1)
	}
	if fileInfo, err := winFileData.GetFileData(os.Args[1]); err != nil {
		os.Exit(2)
	} else {
		fmt.Printf("%+v\n", fileInfo)
	}
}
