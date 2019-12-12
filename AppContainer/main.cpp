#include "SelfWinNT.h"
#include "AppContainer.h"
#include "CommHeader.h"
#include <strsafe.h>
#include <sddl.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <AclAPI.h>

#pragma comment(lib,"Userenv")
#pragma comment(lib,"Shlwapi")
#pragma comment(lib,"kernel32")
#pragma comment(lib,"user32")
#pragma comment(lib,"Advapi32")
#pragma comment(lib,"Ole32")
#pragma comment(lib,"Advapi32.lib")

decltype(NtOpenDirectoryObject) *PFNNtOpenDirectoryObject;
decltype(NtQueryInformationToken) *PFNNtQueryInformationToken;
decltype(NtQuerySecurityObject) *PFNNtQuerySecurityObject;
decltype(RtlConvertSidToUnicodeString) *PFNRtlConvertSidToUnicodeString;
decltype(RtlInitUnicodeString) *PFNRtlInitUnicodeString;
decltype(RtlFreeUnicodeString) *PFNRtlFreeUnicodeString;
decltype(RtlAllocateAndInitializeSid) *PFNRtlAllocateAndInitializeSid;
decltype(RtlFreeSid) *PFNRtlFreeSid;
decltype(RtlGetDaclSecurityDescriptor) *PFNRtlGetDaclSecurityDescriptor;
decltype(RtlLengthSid) *PFNRtlLengthSid;
decltype(RtlCreateAcl) *PFNRtlCreateAcl;
decltype(RtlGetAce) *PFNRtlGetAce;
decltype(RtlIdentifierAuthoritySid) *PFNRtlIdentifierAuthoritySid;
decltype(RtlSubAuthorityCountSid) *PFNRtlSubAuthorityCountSid;
decltype(RtlSubAuthoritySid) *PFNRtlSubAuthoritySid;
decltype(RtlEqualSid) *PFNRtlEqualSid;
decltype(RtlAddAce) *PFNRtlAddAce;
decltype(RtlAddAccessAllowedAce) *PFNRtlAddAccessAllowedAce;
decltype(RtlAddAccessAllowedAceEx) *PFNRtlAddAccessAllowedAceEx;
decltype(RtlCreateSecurityDescriptor) *PFNRtlCreateSecurityDescriptor;
decltype(RtlSetDaclSecurityDescriptor) *PFNRtlSetDaclSecurityDescriptor;
decltype(NtCreateDirectoryObjectEx) *PFNNtCreateDirectoryObjectEx;
decltype(NtDuplicateObject) *PFNNtDuplicateObject;
decltype(RtlAddMandatoryAce) *PFNRtlAddMandatoryAce;
decltype(RtlSetSaclSecurityDescriptor) *PFNRtlSetSaclSecurityDescriptor;
decltype(NtSetSecurityObject) *PFNNtSetSecurityObject;
decltype(NtClose) *PFNNtClose;
decltype(NtCreateSymbolicLinkObject) *PFNNtCreateSymbolicLinkObject;
decltype(NtCreateLowBoxToken) *PFNNtCreateLowBoxToken;

bool InitEssantialFunciton() {
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (hNtdll == NULL) {
		std::cout << "Get ntdll failed" << std::endl;
		return false;
	}
	PFNNtOpenDirectoryObject = SelfGetProcAddress<decltype(NtOpenDirectoryObject)*>(hNtdll, "NtOpenDirectoryObject");
	PFNNtQueryInformationToken = SelfGetProcAddress<decltype(NtQueryInformationToken)* >(hNtdll, "NtQueryInformationToken");
	PFNNtQuerySecurityObject = SelfGetProcAddress<decltype(NtQuerySecurityObject)*>(hNtdll, "NtQuerySecurityObject");
	PFNRtlConvertSidToUnicodeString = SelfGetProcAddress<decltype(RtlConvertSidToUnicodeString)*>(hNtdll, "RtlConvertSidToUnicodeString");
	PFNRtlInitUnicodeString = SelfGetProcAddress<decltype(RtlInitUnicodeString)*>(hNtdll, "RtlInitUnicodeString");
	PFNRtlFreeUnicodeString = SelfGetProcAddress<decltype(RtlFreeUnicodeString)*>(hNtdll, "RtlFreeUnicodeString");
	PFNRtlAllocateAndInitializeSid = SelfGetProcAddress<decltype(RtlAllocateAndInitializeSid)*>(hNtdll, "RtlAllocateAndInitializeSid");
	PFNRtlFreeSid = SelfGetProcAddress<decltype(RtlFreeSid)*>(hNtdll, "RtlFreeSid");
	PFNRtlGetDaclSecurityDescriptor = SelfGetProcAddress<decltype(RtlGetDaclSecurityDescriptor)*>(hNtdll, "RtlGetDaclSecurityDescriptor");
	PFNRtlLengthSid = SelfGetProcAddress<decltype(RtlLengthSid)*>(hNtdll, "RtlLengthSid");
	PFNRtlCreateAcl = SelfGetProcAddress<decltype(RtlCreateAcl)*>(hNtdll, "RtlCreateAcl");
	PFNRtlGetAce = SelfGetProcAddress<decltype(RtlGetAce)*>(hNtdll, "RtlGetAce");
	PFNRtlIdentifierAuthoritySid = SelfGetProcAddress<decltype(RtlIdentifierAuthoritySid)*>(hNtdll, "RtlIdentifierAuthoritySid");
	PFNRtlSubAuthorityCountSid = SelfGetProcAddress<decltype(RtlSubAuthorityCountSid)*>(hNtdll, "RtlSubAuthorityCountSid");
	PFNRtlSubAuthoritySid = SelfGetProcAddress<decltype(RtlSubAuthoritySid)*>(hNtdll, "RtlSubAuthoritySid");
	PFNRtlEqualSid = SelfGetProcAddress<decltype(RtlEqualSid)*>(hNtdll, "RtlEqualSid");
	PFNRtlAddAce = SelfGetProcAddress<decltype(RtlAddAce)*>(hNtdll, "RtlAddAce");
	PFNRtlAddAccessAllowedAce = SelfGetProcAddress<decltype(RtlAddAccessAllowedAce)*>(hNtdll, "RtlAddAccessAllowedAce");
	PFNRtlAddAccessAllowedAceEx = SelfGetProcAddress<decltype(RtlAddAccessAllowedAceEx)*>(hNtdll, "RtlAddAccessAllowedAceEx");
	PFNRtlCreateSecurityDescriptor = SelfGetProcAddress<decltype(RtlCreateSecurityDescriptor)*>(hNtdll, "RtlCreateSecurityDescriptor");
	PFNRtlSetDaclSecurityDescriptor = SelfGetProcAddress<decltype(RtlSetDaclSecurityDescriptor)*>(hNtdll, "RtlSetDaclSecurityDescriptor");
	PFNNtCreateDirectoryObjectEx = SelfGetProcAddress<decltype(NtCreateDirectoryObjectEx)*>(hNtdll, "NtCreateDirectoryObjectEx");
	PFNNtDuplicateObject = SelfGetProcAddress<decltype(NtDuplicateObject)*>(hNtdll, "NtDuplicateObject");
	PFNRtlAddMandatoryAce = SelfGetProcAddress<decltype(RtlAddMandatoryAce)*>(hNtdll, "RtlAddMandatoryAce");
	PFNRtlSetSaclSecurityDescriptor = SelfGetProcAddress<decltype(RtlSetSaclSecurityDescriptor)*>(hNtdll, "RtlSetSaclSecurityDescriptor");
	PFNNtSetSecurityObject = SelfGetProcAddress<decltype(NtSetSecurityObject)*>(hNtdll, "NtSetSecurityObject");
	PFNNtClose = SelfGetProcAddress<decltype(NtClose)*>(hNtdll, "NtClose");
	PFNNtCreateSymbolicLinkObject = SelfGetProcAddress<decltype(NtCreateSymbolicLinkObject)*>(hNtdll, "NtCreateSymbolicLinkObject");
	PFNNtCreateLowBoxToken = SelfGetProcAddress<decltype(NtCreateLowBoxToken)*>(hNtdll, "NtCreateLowBoxToken");

	if (!PFNNtOpenDirectoryObject ||
		!PFNNtQueryInformationToken ||
		!PFNNtQuerySecurityObject ||
		!PFNRtlConvertSidToUnicodeString ||
		!PFNRtlInitUnicodeString || 
		!PFNRtlAllocateAndInitializeSid || 
		!PFNRtlFreeSid ||
		!PFNRtlGetDaclSecurityDescriptor ||
		!PFNRtlLengthSid || 
		!PFNRtlCreateAcl || 
		!PFNRtlGetAce ||
		!PFNRtlIdentifierAuthoritySid ||
		!PFNRtlSubAuthorityCountSid ||
		!PFNRtlSubAuthoritySid || 
		!PFNRtlEqualSid || 
		!PFNRtlAddAce || 
		!PFNRtlAddAccessAllowedAce ||
		!PFNRtlCreateSecurityDescriptor ||
		!PFNRtlSetDaclSecurityDescriptor ||
		!PFNNtCreateDirectoryObjectEx ||
		!PFNNtDuplicateObject || 
		!PFNRtlAddMandatoryAce || 
		!PFNRtlSetSaclSecurityDescriptor ||
		!PFNNtSetSecurityObject ||
		!PFNNtClose ||
		!PFNNtCreateLowBoxToken)
		return false;
	return true;
}

const enum AppContainerHandleList
{
	RootDirectory,			// main directory
	RpcDirectory,			// RPC object directory
	GlobalSymbolicLink,		// Global symbolic link (essantial)
	LocalSymbolicLink,		// Local symbolic link (essantial)
	SessionSymbolicLink,	// Session symbolic link
	NamedPipe				// Named pipe symblic
};

BOOL CreateMyDACL(SECURITY_ATTRIBUTES * pSA) {
	// Create the Security Descriptor with SD format string
	WCHAR szSD[] = L"D:"					// DACL
		L"(A;OICI;GRGWGX;;;AU)"				// generic read/write/execute to authenticated user
		L"(A;OICI;GAGWGX;;;BA)"				// generic read/write/execute to built-in administrator
		L"(A;OICI;GAGWGX;;;s-1-15-2-1)"		// generic read/write/execute to ALL PACKAGES
		L"(A;OICI;GAGWGX;;;SY)";				// generic read/write/execute to system

	if (NULL == pSA)
		return false;

	return ConvertStringSecurityDescriptorToSecurityDescriptor(
			szSD, SDDL_REVISION_1,
			&(pSA->lpSecurityDescriptor),
			NULL
			);
}	

NTSTATUS CreateSelfAppContainerToken(
	_Out_ PHANDLE TokenHandle,
	_In_ HANDLE ExistingTokenHandle,
	_In_ PSECURITY_CAPABILITIES SecurityCapabilities
) {
	// Get Session Token 
	NTSTATUS status = 0;
	DWORD dwTokenSessionID = 0;
	DWORD dwRetLength = 0;
	UNICODE_STRING usAppContainerSID, usRootDirectory, usBNO, usACNO;
	WCHAR Buffer[MAX_PATH] = { 0 };
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE hBaseNamedObjects = nullptr, hAppContainerNamedObjects = nullptr, hRpcControl = nullptr;
	HANDLE HandleList[6] = { nullptr };
	PTOKEN_USER pUserTokenInfo = nullptr;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr, pDirectorySD = nullptr, pRpcControlSD = nullptr;

	UNICODE_STRING usRpcControl;
	UNICODE_STRING usRpcControl2;
	UNICODE_STRING usGlobal;
	UNICODE_STRING usLocal;
	UNICODE_STRING usSession;
	UNICODE_STRING usBNO1;

	PFNRtlInitUnicodeString(&usRpcControl, L"\\RPC Control");
	PFNRtlInitUnicodeString(&usRpcControl2, L"RPC Control");
	PFNRtlInitUnicodeString(&usGlobal, L"Global");
	PFNRtlInitUnicodeString(&usLocal, L"Local");
	PFNRtlInitUnicodeString(&usSession, L"Session");
	PFNRtlInitUnicodeString(&usBNO1, L"\\BaseNamedObjects");

	status = PFNNtQueryInformationToken(
		ExistingTokenHandle,
		TokenSessionId,
		&dwTokenSessionID,
		sizeof(DWORD),
		&dwRetLength
	);

	if (!NT_SUCCESS(status)) {
		std::cout << "Get Token failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	status = PFNRtlConvertSidToUnicodeString(&usAppContainerSID, SecurityCapabilities->AppContainerSid, TRUE);
	if (!NT_SUCCESS(status)) {
		std::cout << "Convert SID failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// Init Session BaseNamedObjects path
	if (dwTokenSessionID != 0) {
		StringCbPrintfW(Buffer, sizeof(Buffer), L"\\Sessions\\%ld\\BaseNamedObjects", dwTokenSessionID);
		PFNRtlInitUnicodeString(&usBNO, Buffer);
	}

	InitializeObjectAttributes(&ObjAttr, &usBNO, 0, NULL, NULL);

	status = PFNNtOpenDirectoryObject(
		&hBaseNamedObjects,
		READ_CONTROL | DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
		&ObjAttr);

	if (!NT_SUCCESS(status)) {
		std::cout << "NtOpenDirectoryObject failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// Get \\Session\\sessionID\\BaseNameObjects PSID
	PFNNtQuerySecurityObject(
		hBaseNamedObjects, DACL_SECURITY_INFORMATION,
		nullptr, 0, &dwRetLength
	);
	pSecurityDescriptor = HeapAlloc(GetProcessHeap(), 0, dwRetLength);
	if (pSecurityDescriptor == nullptr) {
		std::cout << "HeapAlloc failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	PFNNtQuerySecurityObject(
		hBaseNamedObjects, DACL_SECURITY_INFORMATION,
		pSecurityDescriptor, dwRetLength, &dwRetLength);
	
	if (!NT_SUCCESS(status)) {
		std::cout << "NtQuerySecurityObject failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}
	
	// Get User Token Information
	status = PFNNtQueryInformationToken(
		ExistingTokenHandle,
		TokenUser,
		nullptr,
		0,
		&dwRetLength
	);
	pUserTokenInfo = reinterpret_cast<PTOKEN_USER>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRetLength));
	if (pUserTokenInfo == nullptr) {
		std::cout << "HeapAlloc failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	status = PFNNtQueryInformationToken(
		ExistingTokenHandle,
		TokenUser,
		pUserTokenInfo,
		dwRetLength,
		&dwRetLength);

	if (!NT_SUCCESS(status)) {
		std::cout << "NtQueryInformationToken failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// Create AppContainer Security Descriptor for directory
	status = BuildAppContainerSecurityDescriptor(
		pSecurityDescriptor,
		SecurityCapabilities->AppContainerSid,
		pUserTokenInfo->User.Sid,
		false,
		&pDirectorySD
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "BuildAppContainerSecurityDescriptor failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// Create AppContainer Security Descriptor for rpc control
	status = BuildAppContainerSecurityDescriptor(
		pSecurityDescriptor,
		SecurityCapabilities->AppContainerSid,
		pUserTokenInfo->User.Sid,
		true,
		&pRpcControlSD
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "BuildAppContainerSecurityDescriptor(RPC) failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	ZeroMemory(Buffer, sizeof(Buffer));

	// Init AppContainerNamedObjects ID
	StringCbPrintfW(Buffer, sizeof(Buffer), L"\\Sessions\\%ld\\AppContainerNamedObjects", dwTokenSessionID);
	PFNRtlInitUnicodeString(&usACNO, Buffer);

	// Opep nthe AppContainer Path
	InitializeObjectAttributes(&ObjAttr, &usACNO, 0, NULL, NULL);
	status = PFNNtOpenDirectoryObject(
		&hAppContainerNamedObjects,
		DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
		&ObjAttr
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "NtOpenDirectoryObject failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// 1. Creaet AppContaier Directory Object
	// Create AppContainer Directory Object
	// Here is root cause: because the \\Session\\%ld\\AppContainerNamedObjects\\AppContainerSID have not SD, 
	InitializeObjectAttributes(&ObjAttr, &usAppContainerSID, OBJ_INHERIT | OBJ_OPENIF, hAppContainerNamedObjects, pDirectorySD);
	// InitializeObjectAttributes(&ObjAttr, &usAppContainerSID, OBJ_INHERIT | OBJ_OPENIF, hAppContainerNamedObjects, NULL);
	// InitializeObjectAttributes(&ObjAttr, &usAppContainerSID, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, hAppContainerNamedObjects, NULL);

	status = PFNNtCreateDirectoryObjectEx(
		&HandleList[AppContainerHandleList::RootDirectory],
		DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
		//DIRECTORY_ALL_ACCESS,
		&ObjAttr,
		hBaseNamedObjects,
		1
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "Creaet AppContaier Directory Object failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	//Set AppContainer Integrity Level to low
	status = SetKernelObjectIntegrityLevel(
		HandleList[AppContainerHandleList::RootDirectory],
		TOKEN_INTEGRITY_LEVELS_LIST::LowLevel
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "Creaet AppContaier Low level failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// 2. Create RPC Control Directory Object
	// First initialize \\RpcControl to open this handle
	InitializeObjectAttributes(&ObjAttr, &usRpcControl, 0, NULL, NULL);
	status = PFNNtOpenDirectoryObject(
		&hRpcControl,
		DIRECTORY_QUERY | DIRECTORY_TRAVERSE,
		&ObjAttr
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "Open RPC failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// Initialize the AppContainer RPC Control Directory OBJECT_ATTRIBUTES for create Directory handle
	InitializeObjectAttributes(
		&ObjAttr, &usRpcControl2,
		OBJ_INHERIT | OBJ_OPENIF,
		HandleList[AppContainerHandleList::RootDirectory],
		pRpcControlSD);
	
	status = PFNNtCreateDirectoryObjectEx(
		&HandleList[AppContainerHandleList::RpcDirectory],
		DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
		&ObjAttr,
		hRpcControl,
		1);
	if (!NT_SUCCESS(status)) {
		std::cout << "Create Directory RPC Control failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	status = SetKernelObjectIntegrityLevel(
		HandleList[AppContainerHandleList::RpcDirectory],
		TOKEN_INTEGRITY_LEVELS_LIST::LowLevel);
	if (!NT_SUCCESS(status)) {
		std::cout << "Create Directory RPC Low Level failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	ZeroMemory(Buffer, sizeof(Buffer));
	// 3/4. AppContainerNamedObjects Global/Local Symbolic Link Initialize (with sid)
	// [VERY IMPORTANT HERE]!!!!!!!!!!
	// Open Symbolic Path to create global symbolic
	StringCbPrintfW(
		Buffer, sizeof(Buffer),
		L"\\Sessions\\%d\\AppContainerNamedObjects\\%ws",
		TokenSessionId,
		usAppContainerSID.Buffer, usAppContainerSID.Length);
	PFNRtlInitUnicodeString(&usRootDirectory, Buffer);

	InitializeObjectAttributes(
		&ObjAttr,
		&usGlobal,
		OBJ_INHERIT | OBJ_OPENIF,
		HandleList[AppContainerHandleList::RootDirectory],
		pDirectorySD
	);

	// AppContainer create Global symbolic object
	// it will like: Name->Global Type->SymbolicLink SymLink->\BaseNamedObjects
	status = PFNNtCreateSymbolicLinkObject(
		&HandleList[AppContainerHandleList::GlobalSymbolicLink],
		SYMBOLIC_LINK_ALL_ACCESS,
		&ObjAttr,
		&usBNO1
	);

	if (!NT_SUCCESS(status)) {
		std::cout << "Create Global Link failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	InitializeObjectAttributes(
		&ObjAttr,
		&usLocal,
		OBJ_INHERIT | OBJ_OPENIF,
		HandleList[AppContainerHandleList::RootDirectory],
		pDirectorySD
	);

	// AppContainer create Local symbolic object
	// it will like: Name->Local Type->SymbolicLink SymLink->\Session\sessionID\AppContainerNamedObjects\S-1-4-5-6-7--...
	status = PFNNtCreateSymbolicLinkObject(
		&HandleList[AppContainerHandleList::LocalSymbolicLink],
		SYMBOLIC_LINK_ALL_ACCESS,
		&ObjAttr,
		&usRootDirectory
	);

	if (!NT_SUCCESS(status)) {
		std::cout << "Create Local Link  failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// 5. Initialize SessionHandle
	InitializeObjectAttributes(
		&ObjAttr,
		&usSession,
		OBJ_INHERIT | OBJ_OPENIF,
		HandleList[AppContainerHandleList::RootDirectory],
		pDirectorySD
	);

	// AppContainer create session symbolic link object
	// it will look like Local Symboliclink
	status = PFNNtCreateSymbolicLinkObject(
		&HandleList[AppContainerHandleList::SessionSymbolicLink],
		SYMBOLIC_LINK_ALL_ACCESS,
		&ObjAttr,
		&usRootDirectory);

	if (!NT_SUCCESS(status)) {
		std::cout << "Create Local Link  failed with error :" << std::hex << status << std::endl;
		goto CLEAN;
	}

	// 6. Initailize Pipe Line
	// Try to SKIP
	// MAY CAUSE BUG

	// Create AppContainer Low Box Token
	InitializeObjectAttributes(&ObjAttr, NULL, NULL, 0, 0);
	//HandleList[AppContainerHandleList::RootDirectory] = NULL;
	//HandleList[AppContainerHandleList::NamedPipe] = NULL;
	//HandleList[AppContainerHandleList::LocalSymbolicLink] = NULL;
	//HandleList[AppContainerHandleList::GlobalSymbolicLink] = NULL;
	//HandleList[AppContainerHandleList::RpcDirectory] = NULL;
	//HandleList[AppContainerHandleList::SessionSymbolicLink] = NULL;
	status = PFNNtCreateLowBoxToken(
		TokenHandle,
		ExistingTokenHandle,
		TOKEN_ALL_ACCESS,
		&ObjAttr,
		SecurityCapabilities->AppContainerSid,
		SecurityCapabilities->CapabilityCount,
		SecurityCapabilities->Capabilities,
		1,
		HandleList
	);

CLEAN:
	for (int i = 0; i < 5; i++) {
		PFNNtClose(HandleList[i]);
	}
	PFNNtClose(hRpcControl);
	PFNNtClose(hAppContainerNamedObjects);
	if (pRpcControlSD != nullptr) {
		LocalFree(pRpcControlSD);
	}
	if (pDirectorySD != nullptr) {
		LocalFree(pDirectorySD);
	}
	if (pUserTokenInfo != nullptr) {
		LocalFree(pUserTokenInfo);
	}
	if (pSecurityDescriptor != nullptr) {
		LocalFree(pSecurityDescriptor);
	}
	PFNRtlFreeUnicodeString(&usAppContainerSID);

	return status;
}

WELL_KNOWN_SID_TYPE capabilitiyTypeList[] =
{
		WinCapabilityInternetClientSid,
		WinCapabilityInternetClientServerSid,
		WinCapabilityPrivateNetworkClientServerSid,
};

bool ChangeAppContainerSecurityDescriptor(HANDLE hChild) {
	UNICODE_STRING usSApp;
	WCHAR Buffer[MAX_PATH * 2];
	LPWSTR wszAppContainerSID = nullptr;
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE hAppContainerRootDir = nullptr;
	NTSTATUS status = 0;
	HANDLE hToken = nullptr;
	DWORD dwRetLength, dwRetStatus ,cbNewACLSize;
	_TOKEN_APPCONTAINER_INFORMATION * tkAppContainer;
	DWORD dwSessionID = 0;
	PACL pOldACL = nullptr, pNewACL = nullptr;
	PACCESS_ALLOWED_ACE pTempACE;
	PSECURITY_DESCRIPTOR  pOldSD = nullptr;

	OpenProcessToken(hChild, TOKEN_ALL_ACCESS, &hToken);
	GetTokenInformation(hToken, TokenAppContainerSid, NULL, NULL, &dwRetLength);
	tkAppContainer = reinterpret_cast<_TOKEN_APPCONTAINER_INFORMATION *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRetLength));
	if (!GetTokenInformation(hToken, TokenAppContainerSid, tkAppContainer, dwRetLength, &dwRetLength)) {
		std::cout << "Get User Token faield with error code 0x:" << std::hex << GetLastError() << std::endl;
		goto CHANGEEND;
	}
	if (!GetTokenInformation(hToken, TokenSessionId, &dwSessionID, sizeof(DWORD), &dwRetLength)) {
		std::cout << "Get Session ID faield with error code 0x:" << std::hex << GetLastError() << std::endl;
		goto CHANGEEND;
	}
	ConvertSidToStringSidW(tkAppContainer->TokenAppContainer, &wszAppContainerSID);
	if (wszAppContainerSID == nullptr) {
		std::cout << "Convert SID failed.." << std::endl;
		goto CHANGEEND;
	}
	// Query Session number

	wsprintf(Buffer, L"\\Sessions\\%d\\AppContainerNamedObjects\\%ws", dwSessionID, wszAppContainerSID);
	std::wcout << L"Now we get path is " << Buffer << std::endl;
	PFNRtlInitUnicodeString(&usSApp, Buffer);

	InitializeObjectAttributes(&ObjAttr, &usSApp, NULL, 0, 0);
	status = PFNNtOpenDirectoryObject(
		&hAppContainerRootDir,
		DIRECTORY_QUERY | DIRECTORY_TRAVERSE |
		DIRECTORY_CREATE_OBJECT | DIRECTORY_CREATE_SUBDIRECTORY,
		&ObjAttr
	);
	if (!NT_SUCCESS(status)) {
		std::cout << "NtOpenDirectoryObject failed with error :" << std::hex << status << std::endl;
		goto CHANGEEND;
	}
	std::cout << "Open the Root Directory handle:" << hAppContainerRootDir << std::endl;

	dwRetStatus = GetSecurityInfo(
		hAppContainerRootDir,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL, NULL,
		&pOldACL, NULL,
		&pOldSD
	);
	if (dwRetStatus != ERROR_SUCCESS) {
		std::cout << "Get security info failed with error code :" << std::hex << dwRetStatus << std::endl;
		goto CHANGEEND;
	}

	cbNewACLSize = pOldACL->AclSize;
	cbNewACLSize += GetLengthSid(tkAppContainer->TokenAppContainer);
	cbNewACLSize += sizeof(ACCESS_ALLOWED_ACE);
	pNewACL = reinterpret_cast<PACL>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbNewACLSize));
	InitializeAcl(pNewACL, cbNewACLSize, pOldACL->AclRevision);
	for (ULONG i = 0; NT_SUCCESS(PFNRtlGetAce(pOldACL, i, (PVOID*)&pTempACE)); i++) {
		// add ACE for new ACL
		AddAce(pNewACL, pOldACL->AclRevision, i, pTempACE, pTempACE->Header.AceSize);
	}
	// add new ACE to root directory
	if (!AddAccessAllowedAce(
		pNewACL,
		pOldACL->AclRevision,
		DIRECTORY_ALL_ACCESS,
		tkAppContainer->TokenAppContainer
	)) {
		std::cout << "AddAccessAllowedAce failed with error :" << std::hex << GetLastError() << std::endl;
		goto CHANGEEND;
	}
	SetSecurityInfo(
		hAppContainerRootDir,
		SE_FILE_OBJECT,
		DACL_SECURITY_INFORMATION,
		NULL, NULL,
		pNewACL,
		NULL
	);
	if (dwRetStatus != ERROR_SUCCESS) {
		std::cout << "Set security info failed with error code :" << std::hex << dwRetStatus << std::endl;
		goto CHANGEEND;
	}
	//SetSecurityDescriptorDacl()
	
	
CHANGEEND:
	if (wszAppContainerSID != nullptr)
		LocalFree(wszAppContainerSID);
	if (pOldACL != nullptr)
		LocalFree(pOldACL);
	if (pOldSD != nullptr)
		LocalFree(pOldSD);
	if (tkAppContainer != nullptr)
		HeapFree(GetProcessHeap(), NULL, tkAppContainer);
	return status == 0;
}
int wmain(int argc, WCHAR* argv[]) {

	HANDLE hEvent = NULL;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = FALSE;
	if (!CreateMyDACL(&sa)) {
		std::cout << "Create the security descriptor failed" << std::endl;
		return -1;
	}

	hEvent = CreateEvent(&sa, false, false, COMMONOBJECT);
	if (hEvent == NULL) {
		std::cout << "The Common event create failed" << std::endl;
		return -1;
	}
	if (!InitEssantialFunciton()) {
		return -1;
	}
	HANDLE hLowBoxToken = nullptr;
	HANDLE hCPHandle = GetCurrentProcessToken();
	HANDLE hCurrentProcess = GetCurrentProcess();
	HANDLE hRealCurrentProcess = nullptr, hRealCPHandle = nullptr;
	SECURITY_CAPABILITIES SecurityCapabilities;
	SID_AND_ATTRIBUTES CapabilitiesList[3];

	WCHAR lpApplicationName[] = L"C:\\Windows\\System32\\cmd.exe";
	WCHAR* lpAppBuffer = nullptr;
	for (int i = 0; i < sizeof(capabilitiyTypeList) / sizeof(WELL_KNOWN_SID_TYPE); i++)
	{
		DWORD dwSIDSize = SECURITY_MAX_SID_SIZE;
		CapabilitiesList[i].Sid = new unsigned char[SECURITY_MAX_SID_SIZE];
		CapabilitiesList[i].Attributes = SE_GROUP_ENABLED;
		if (!CreateWellKnownSid(capabilitiyTypeList[i], NULL, CapabilitiesList[i].Sid, &dwSIDSize) ||
			!IsWellKnownSid(CapabilitiesList[i].Sid, capabilitiyTypeList[i]))
		{
			std::cout << "sth error at create well known sid " << std::endl;
			return -1;
		}
	}

	WCHAR wszAppContainerName[] = L"TestLowBox12456";
	PSID pAppContainerSID = nullptr;
	DWORD retValue = 0;
	retValue = CreateAppContainerProfile(
		wszAppContainerName,
		wszAppContainerName,
		wszAppContainerName,
		nullptr, 0,
		&pAppContainerSID);
	if (retValue != S_OK) {
		if (HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == retValue){
			DeriveAppContainerSidFromAppContainerName(wszAppContainerName, &pAppContainerSID);
		}
		else{
			std::cout << "Something error happen:" << std::hex << retValue << std::endl;
			return -1;
		}
	}
	bool bOpenSuccess = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hRealCPHandle);
	SecurityCapabilities = { pAppContainerSID, CapabilitiesList, 3 ,0 };
	// Here we will create appcontainer token
	CreateSelfAppContainerToken(&hLowBoxToken, hRealCPHandle, &SecurityCapabilities);
	if (hLowBoxToken == NULL) {
		std::cout << "Create LowBox Token failed" << std::endl;
		return -1;
	}
	// try to create a process with token
	STARTUPINFOEX StartupInfoEx = { 0 };
	PROCESS_INFORMATION ProcessInfo = { 0 };
	StartupInfoEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	SIZE_T cbAttributeListSize = 0;
	InitializeProcThreadAttributeList(NULL, 3, 0, &cbAttributeListSize);
	StartupInfoEx.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAttributeListSize);
	// Initialize thread
	if (InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 3, 0, &cbAttributeListSize))
	{
		// Update startup to generate app container process
		if (UpdateProcThreadAttribute(
			StartupInfoEx.lpAttributeList,
			0,
			PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
			&SecurityCapabilities,
			sizeof(SecurityCapabilities),
			NULL,
			NULL))
		{
			lpAppBuffer = reinterpret_cast<WCHAR*>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_PATH * 2));
			if (argc >= 2) {
				wcscpy_s(lpAppBuffer, MAX_PATH, argv[1]);
			}
			else {
				wcscpy_s(lpAppBuffer, MAX_PATH, lpApplicationName);
			}
			if (CreateProcessAsUserW(
				hLowBoxToken, lpAppBuffer, NULL, nullptr, nullptr, FALSE,
				EXTENDED_STARTUPINFO_PRESENT | 
				CREATE_UNICODE_ENVIRONMENT ,
				NULL, NULL, (LPSTARTUPINFOW)&StartupInfoEx, &ProcessInfo))
			{
				std::cout << "Create Process success!" << std::endl;
			}
			DeleteProcThreadAttributeList(StartupInfoEx.lpAttributeList);
		}
	}
	Sleep(3000);
	HANDLE hChild = ProcessInfo.hProcess;
	ChangeAppContainerSecurityDescriptor(hChild);
	FreeSid(pAppContainerSID);
	HeapFree(GetProcessHeap(), NULL, lpAppBuffer);
	Sleep(10000);
	CloseHandle(hEvent);
	LocalFree(sa.lpSecurityDescriptor);
	//Sleep(100000);
	std::cout << "Wellll" << std::endl;
	//HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	//if (hNtdll == NULL) {
	//	std::cout << "Get ntdll failed" << std::endl;
	//	return -1;
	//}
	////auto PFNNtOpenDirectoryObject = SelfGetProcAddress<decltype(NtOpenDirectoryObject)*>(hNtdll, "NtOpenDirectoryObject");
	//PFNNtQueryInformationToken = SelfGetProcAddress<decltype(NtQueryInformationToken)* > (hNtdll, "NtQueryInformationToken");
	////std::cout << "The function address is " << PFNNtOpenDirectoryObject << std::endl;
	//char buffer[261] = { 0 };
	//TOKEN_OWNER *token_owner = (TOKEN_OWNER*)buffer;
	//DWORD dwRetSize = 0;
	//DWORD sessionID;

	//PFNNtQueryInformationToken(
	//	GetCurrentProcessToken(),
	//	TokenOwner,
	//	token_owner,
	//	sizeof(char) * 261,
	//	&dwRetSize
	//);
	//LPWSTR wszSIDPtr;
	//ConvertSidToStringSid(token_owner->Owner, &wszSIDPtr);
	//std::wcout << (WCHAR*)wszSIDPtr << std::endl;
	//if(wszSIDPtr != nullptr)
	//	LocalFree(wszSIDPtr);
	return 0;
}