// AppContainerTest.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "../AppContainer/CommHeader.h"
#include "../AppContainer/SelfWinNT.h"
#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <UserEnv.h>
#include <Shlwapi.h>

#pragma comment(lib,"Userenv")
#pragma comment(lib,"Shlwapi")
#pragma comment(lib,"kernel32")
#pragma comment(lib,"user32")
#pragma comment(lib,"Advapi32")
#pragma comment(lib,"Ole32")


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

BOOL ChangeAppContainerSD(PSID AppContainerSID, DWORD dwSessionID) {
	// Try to open RootDirectory for AppContainer
	// \Sessions\%ld\AppContainerNamedObjects\{AppContainerSID}
	UNICODE_STRING usSApp;
	WCHAR Buffer[MAX_PATH*2];
	LPWSTR wszTokenSID = nullptr;
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE hAppContainerRootDir = nullptr;
	NTSTATUS status = 0;
	ConvertSidToStringSidW(AppContainerSID, &wszTokenSID);
	if (wszTokenSID == nullptr) {
		std::cout << "Convert SID failed.." << std::endl;
		goto CHANGEEND;
	}
	// Query Session number
	wsprintf(Buffer, L"\\Sessions\\%ld\\AppContainerNamedObjects", dwSessionID);
	std::wcout << L"Now we get path is " << Buffer << std::endl;
	// In fact, here will failed. Because AppContainer have no permission for this path,
	// So it could not try to search path even from root.
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

CHANGEEND:
	if (wszTokenSID == nullptr)
		LocalFree(wszTokenSID);
	return status == 0;
}
int main()
{
	if (!InitEssantialFunciton()) {
		std::cout << "Initialize function failed" << std::endl;
		return -1;
	}
	HANDLE hToken = GetCurrentProcessToken();
	DWORD dwRetLength;
	LPWSTR wszTokenSID = nullptr;
	_TOKEN_APPCONTAINER_INFORMATION * tkAppContainer;
	DWORD dwSessionID = 0;

	GetTokenInformation(hToken, TokenAppContainerSid, NULL, NULL, &dwRetLength);
	tkAppContainer = reinterpret_cast<_TOKEN_APPCONTAINER_INFORMATION *>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRetLength));

	if (!GetTokenInformation(hToken, TokenAppContainerSid, tkAppContainer, dwRetLength, &dwRetLength)) {
		std::cout << "Get User Token faield with error code 0x:" << std::hex << GetLastError() << std::endl;
		return -1;
	}
	if (!GetTokenInformation(hToken, TokenSessionId, &dwSessionID, sizeof(DWORD), &dwRetLength)) {
		std::cout << "Get Session ID faield with error code 0x:" << std::hex << GetLastError() << std::endl;
			return -1;
	}
	
	//ChangeAppContainerSD(tkAppContainer->TokenAppContainer, dwSessionID);
	ConvertSidToStringSidW(tkAppContainer->TokenAppContainer, &wszTokenSID);
	if(wszTokenSID != nullptr)
		std::wcout << wszTokenSID << std::endl;
	HANDLE mEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, COMMONOBJECT);
	std::cout << "mEvent is :" << std::hex << mEvent << std::endl;
	std::cout << "GetLastError is :" << std::hex << GetLastError() << std::endl;
	//LocalFree(tkAppContainer);
	HeapFree(GetProcessHeap(), NULL, tkAppContainer);
	LocalFree(wszTokenSID);
	Sleep(3000);
	mEvent = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, COMMONOBJECT);
	std::cout << "mEvent is :" << std::hex << mEvent << std::endl;
	std::cout << "GetLastError is :" << std::hex << GetLastError() << std::endl;
	Sleep(10000);
	//system("pause");
	return 0;
}
