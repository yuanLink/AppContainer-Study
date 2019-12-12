// AppContainerTool.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <strsafe.h>
#include <Windows.h>
#include <sddl.h>
#include <UserEnv.h>
#include <Shlwapi.h>
#include <AclAPI.h>
#include <iostream>
#include <winternl.h>
#include "../AppContainer/SelfWinNT.h"

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


bool AddSidToAcl(PSID sid,
	ACL* old_dacl,
	ACCESS_MODE access_mode,
	ACCESS_MASK access,
	ACL** new_dacl) {
	//define ace by oneself
	EXPLICIT_ACCESS new_access = { 0 };
	new_access.grfAccessMode = access_mode;
	new_access.grfAccessPermissions = access;
	new_access.grfInheritance = NO_INHERITANCE;

	new_access.Trustee.pMultipleTrustee = nullptr;
	new_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	new_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	new_access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);

	if (ERROR_SUCCESS != SetEntriesInAcl(1, &new_access, old_dacl, new_dacl)) {
		return false;
	}
	return true;
}

bool AddKnownSidToObject(HANDLE object,
	SE_OBJECT_TYPE object_type,
	PSID sid,
	ACCESS_MODE access_mode,
	ACCESS_MASK access) {

	PSECURITY_DESCRIPTOR descriptor = nullptr;
	PACL old_dacl = nullptr;
	PACL new_dacl = nullptr;

	if (ERROR_SUCCESS != GetSecurityInfo(object, object_type, DACL_SECURITY_INFORMATION, nullptr,
		nullptr, &old_dacl, nullptr, &descriptor))
		return false;

	if (!AddSidToAcl(sid, old_dacl, access_mode, access, &new_dacl)) {
		LocalFree(descriptor);
		return false;
	}

	DWORD result = SetSecurityInfo(object, object_type, DACL_SECURITY_INFORMATION, nullptr,
		nullptr, new_dacl, nullptr);

	LocalFree(new_dacl);
	LocalFree(descriptor);

	return false;
}

bool ReplacePackageSidInDacl(
	HANDLE object,
	SE_OBJECT_TYPE object_type,
	PSID package_sid,
	ACCESS_MASK access
) {
	if(!AddKnownSidToObject(object, object_type, package_sid, REVOKE_ACCESS, 0))
}
bool ChangeAppContainerSecurityDescriptor(HANDLE hChild) {
	UNICODE_STRING usSApp;
	WCHAR Buffer[MAX_PATH * 2];
	LPWSTR wszAppContainerSID = nullptr;
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE hAppContainerRootDir = nullptr;
	NTSTATUS status = 0;
	HANDLE hToken = nullptr;
	DWORD dwRetLength, dwRetStatus, cbNewACLSize;
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
	cbNewACLSize += sizeof(ACCESS_ALLOWED_ACE) * 9;
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
	if (!AddAccessAllowedAceEx(
		pNewACL,
		pOldACL->AclRevision,
		OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
		GENERIC_ALL,
		tkAppContainer->TokenAppContainer
	)) {
		std::cout << "AddAccessAllowedAceEX failed with error :" << std::hex << GetLastError() << std::endl;
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

int main()
{
	DWORD dwPID;
	HANDLE hProcess;

	if (!InitEssantialFunciton()) {
		std::cout << "Initialize essential function failed" << std::endl;
		return -1;
	}
	

	std::cout << "Input the number of the pid:" << std::endl;
	std::cin >> dwPID;
	std::cout << std::endl << "Now we try to add new ACE for object" << std::endl;
	
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, dwPID);
	if (!hProcess) {
		std::cout << "Get the process handle failed with error code:" << GetLastError() << std::endl;
		return -1;
	}
	ChangeAppContainerSecurityDescriptor(hProcess);
	std::cout << "Finish" << std::endl;
	return 0;
}
