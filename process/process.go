package process

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")
	modwtsapi32 = syscall.NewLazyDLL("wtsapi32.dll")
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")

	procOpenProcess                  = modkernel32.NewProc("OpenProcess")
	procCloseHandle                  = modkernel32.NewProc("CloseHandle")
	procCreateProcessAsUser          = modkernel32.NewProc("CreateProcessAsUserW")
	procTerminateProcess             = modkernel32.NewProc("TerminateProcess")
	procWTSGetActiveConsoleSessionId = modkernel32.NewProc("WTSGetActiveConsoleSessionId")
	proProcessIdToSessionId          = modkernel32.NewProc("ProcessIdToSessionId")

	procOpenProcessToken      = modadvapi32.NewProc("OpenProcessToken")
	procDuplicateTokenEx      = modadvapi32.NewProc("DuplicateTokenEx")
	procWTSEnumerateSessionsW = modwtsapi32.NewProc("WTSEnumerateSessionsW")
)

const (
	PROCESS_QUERY_INFORMATION = 0x0400
	TOKEN_QUERY               = 0x0008
	MAXIMUM_ALLOWED           = 0x02000000

	SecurityAnonymous      SECURITY_IMPERSONATION_LEVEL = 0
	SecurityIdentification SECURITY_IMPERSONATION_LEVEL = 1
	SecurityImpersonation  SECURITY_IMPERSONATION_LEVEL = 2
	SecurityDelegation     SECURITY_IMPERSONATION_LEVEL = 3

	CREATE_UNICODE_ENVIRONMENT = 0x00000400
	CREATE_NEW_CONSOLE         = 0x00000010

	TokenPrimary       TOKEN_TYPE = 1
	TokenImpersonation TOKEN_TYPE = 2

	WTSActive = 0
)

type SECURITY_IMPERSONATION_LEVEL uint32
type TOKEN_TYPE uint32

type WTS_SESSION_INFO struct {
	SessionID      windows.Handle
	WinStationName *uint16
	State          uint32
}

func StartProcessAsCurrentUser(appPath string) (syscall.ProcessInformation, error) {
	var winLogonProcessName = "winlogon.exe"
	var winLogonPid uint32
	var ptoken syscall.Handle
	var hUserToken syscall.Handle
	var procInfo syscall.ProcessInformation
	var buffer [512]uint16

	var sessionId uint32 = 0xFFFFFFFF

	sessionList, err := WTSEnumerateSessions()
	if err != nil {
		return procInfo, err
	}

	for i := range sessionList {
		if sessionList[i].State == 0 {
			sessionId = uint32(sessionList[i].SessionID)
		}
	}

	if sessionId == 0xFFFFFFFF {
		sessionId = WTSGetActiveConsoleSessionId()
	}

	utf16, _ := syscall.UTF16FromString(winLogonProcessName)
	copy(buffer[:], utf16)

	hSnap, _ := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	defer syscall.CloseHandle(hSnap)
	e := syscall.ProcessEntry32{}
	e.Size = uint32(unsafe.Sizeof(e))

	for {
		if err := syscall.Process32Next(hSnap, &e); err != nil {
			break
		}

		cSessionId := ProcessIdToSessionId(e.ProcessID)

		if syscall.UTF16ToString(e.ExeFile[:]) == winLogonProcessName && cSessionId == sessionId {
			winLogonPid = e.ProcessID
			break
		}
	}

	processPtr, _, _ := procOpenProcess.Call(uintptr(0x2000000), uintptr(0), uintptr(winLogonPid))
	if processPtr == 0 {
		return procInfo, fmt.Errorf("OpenProcess failed")
	}

	_, _, _ = procOpenProcessToken.Call(uintptr(processPtr), uintptr(0x0002), uintptr(unsafe.Pointer(&ptoken)))
	procCloseHandle.Call(uintptr(processPtr))
	if ptoken == 0 {
		return procInfo, fmt.Errorf("OpenProcessToken failed")
	}

	var sa syscall.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))

	_, _, _ = procDuplicateTokenEx.Call(
		uintptr(ptoken),
		uintptr(MAXIMUM_ALLOWED),
		uintptr(unsafe.Pointer(&sa)),
		uintptr(SecurityImpersonation),
		uintptr(TokenPrimary),
		uintptr(unsafe.Pointer(&hUserToken)),
	)

	procCloseHandle.Call(uintptr(ptoken))
	if hUserToken == 0 {
		return procInfo, fmt.Errorf("DuplicateTokenEx failed")
	}

	var dwCreationFlags = CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE
	var cmdLine = ""
	var workDir = filepath.Dir(appPath)

	var startInfo syscall.StartupInfo
	startInfo.Cb = uint32(unsafe.Sizeof(startInfo))
	startInfo.Desktop = syscall.StringToUTF16Ptr("winsta0\\default")

	lpApplicationName, _ := syscall.UTF16PtrFromString(appPath)
	lpCommandLine, _ := syscall.UTF16PtrFromString(cmdLine)
	lpCurrentDirectory, _ := syscall.UTF16PtrFromString(workDir)

	ret, _, err := procCreateProcessAsUser.Call(
		uintptr(hUserToken),
		uintptr(unsafe.Pointer(lpApplicationName)),
		uintptr(unsafe.Pointer(lpCommandLine)),
		0,
		0,
		0,
		uintptr(dwCreationFlags),
		0,
		uintptr(unsafe.Pointer(lpCurrentDirectory)),
		uintptr(unsafe.Pointer(&startInfo)),
		uintptr(unsafe.Pointer(&procInfo)),
	)

	procCloseHandle.Call(uintptr(hUserToken))
	if ret == 0 {
		return procInfo, fmt.Errorf("CreateProcessAsUser %v", err)
	}
	return procInfo, nil
}

func TerminateProcess(handle uintptr) {
	procTerminateProcess.Call(handle)
}

func WTSGetActiveConsoleSessionId() uint32 {
	var sessionId uint32
	procWTSGetActiveConsoleSessionId.Call(uintptr(unsafe.Pointer(&sessionId)))
	return sessionId
}

func ProcessIdToSessionId(pid uint32) uint32 {
	var sessionId uint32
	proProcessIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sessionId)))
	return sessionId
}

func WTSEnumerateSessions() ([]*WTS_SESSION_INFO, error) {
	var (
		sessionInformation windows.Handle      = windows.Handle(0)
		sessionCount       int                 = 0
		sessionList        []*WTS_SESSION_INFO = make([]*WTS_SESSION_INFO, 0)
	)

	if returnCode, _, err := procWTSEnumerateSessionsW.Call(0, 0, 1, uintptr(unsafe.Pointer(&sessionInformation)), uintptr(unsafe.Pointer(&sessionCount))); returnCode == 0 {
		return nil, fmt.Errorf("call native WTSEnumerateSessionsW: %s", err)
	}

	structSize := unsafe.Sizeof(WTS_SESSION_INFO{})
	current := uintptr(sessionInformation)
	for i := 0; i < sessionCount; i++ {
		sessionList = append(sessionList, (*WTS_SESSION_INFO)(unsafe.Pointer(current)))
		current += structSize
	}

	return sessionList, nil
}
