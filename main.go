package main

import (
	"fmt"
	"os"
	"runas/token"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func help() {
	fmt.Println("Usage:")
	fmt.Println("\t- List available users: gorunAs.exe list")
	fmt.Println("\t- Run command: gorunAs.exe exec <username> <command>")
}

func main() {
	fmt.Println(`                                _        
	_ __   ___ __ _ _   _  __ _   / \   ___ 
   | '_ \ / _ |__  | | | |/ _  | / _ \ |__ \
   | |_) | (_) | | | |_| | | | |/ ___ \/ __/
   | .__/ \___/  |_|_.__/|_| |_/_/   \_\___|
	\___|  v1.0
	`)
	if len(os.Args) < 2 {
		help()
		return
	}

	err := token.SetupPrivilege()
	if err != nil {
		fmt.Println(err)
		return
	}

	listToken, err := token.ListAllToken()
	if err != nil {
		fmt.Println(err)
		return
	}

	option := strings.ToLower(os.Args[1])
	switch option {
	case "list":
		for _, t := range listToken {
			fmt.Printf("User: %s [ProcessId: %v]\n", t.FullName, t.ProcessId)
		}
		return
	case "exec":
		if len(os.Args) < 4 {
			help()
			return
		}

		username := strings.ToLower(strings.TrimSpace(os.Args[2]))
		exeFile := os.Args[3]

		if len(username) < 1 {
			help()
			return
		}

		if len(exeFile) == 0 {
			exeFile = "cmd.exe"
		}

		found := false

		for _, t := range listToken {
			if strings.ToLower(t.FullName) == username {
				found = true
				var sa syscall.SecurityAttributes
				sa.Length = uint32(unsafe.Sizeof(sa))

				var hUserToken windows.Token
				err = windows.DuplicateTokenEx(windows.Token(t.Handle), windows.TOKEN_ALL_ACCESS, nil, windows.SecurityImpersonation, windows.TokenPrimary, &hUserToken)
				if err != nil {
					fmt.Printf("Failed to DuplicateTokenEx: %v - ProcessId: %v\n", err, t.ProcessId)
					continue
				}

				// err = windows.SetTokenInformation(windows.Token(hUserToken), windows.TokenSessionId, (*byte)(unsafe.Pointer(&currentSessionId1)), uint32(unsafe.Sizeof(currentSessionId1)))
				// if err != nil {
				// 	fmt.Printf("Failed to set token information: %v\n", err)
				// 	return
				// }

				command := windows.StringToUTF16Ptr(exeFile)
				var si syscall.StartupInfo
				var pi syscall.ProcessInformation
				si.Cb = uint32(unsafe.Sizeof(si))

				// err = windows.CreateProcessAsUser(windows.Token(hUserToken), nil, command, nil, nil, false, windows.CREATE_UNICODE_ENVIRONMENT, nil, nil, &si, &pi)
				// if err != nil {
				// 	fmt.Printf("Failed to create process: %v\n", err)
				// 	return
				// }

				err := token.CreateProcessWithTokenW(windows.Handle(hUserToken), 0, nil, command, 0, nil, nil, &si, &pi)
				if err != nil {
					fmt.Printf("CreateProcessWithTokenW failed: %v - ProcessId: %v\n", err, t.ProcessId)
					continue
				}
				break
			}
		}

		if !found {
			fmt.Println("user not found")
		}
	default:
		help()
	}

}
