package main

import (
	"fmt"
	"runas/process"
)

func main() {
	procInfo, err := process.StartProcessAsCurrentUser("C:\\Windows\\System32\\cmd.exe")
	if err != nil {

	}

	fmt.Println(procInfo)
	for {

	}
}
