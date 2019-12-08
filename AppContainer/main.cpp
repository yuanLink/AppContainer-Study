#include "SelfWinNT.h"
#include <sddl.h>

decltype(NtOpenDirectoryObject) *PFNNtOpenDirectoryObject;
decltype(NtQueryInformationToken) *PFNNtQueryInformationToken;
decltype(NtQuerySecurityObject) *PFNNtQuerySecurityObject;


bool InitEssantialFunciton() {
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (hNtdll == NULL) {
		std::cout << "Get ntdll failed" << std::endl;
		return false;
	}
	PFNNtOpenDirectoryObject = SelfGetProcAddress<decltype(NtOpenDirectoryObject)*>(hNtdll, "NtOpenDirectoryObject");
	PFNNtQueryInformationToken = SelfGetProcAddress<decltype(NtQueryInformationToken)* >(hNtdll, "NtQueryInformationToken");
	PFNNtQuerySecurityObject = SelfGetProcAddress<decltype(NtQuerySecurityObject)*>(hNtdll, "NtQuerySecurityObject");

}

NTSTATUS CreateAppContainerToken(
	_Out_ PHANDLE TokenHandle,
	_In_ HANDLE ExistingTokenHandle,
	_In_ PSECURITY_CAPABILITIES SecurityCapabilities
) {
	
}

int main() {
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (hNtdll == NULL) {
		std::cout << "Get ntdll failed" << std::endl;
		return -1;
	}
	//auto PFNNtOpenDirectoryObject = SelfGetProcAddress<decltype(NtOpenDirectoryObject)*>(hNtdll, "NtOpenDirectoryObject");
	PFNNtQueryInformationToken = SelfGetProcAddress<decltype(NtQueryInformationToken)* > (hNtdll, "NtQueryInformationToken");
	//std::cout << "The function address is " << PFNNtOpenDirectoryObject << std::endl;
	char buffer[261] = { 0 };
	TOKEN_OWNER *token_owner = (TOKEN_OWNER*)buffer;
	DWORD dwRetSize = 0;
	DWORD sessionID;

	PFNNtQueryInformationToken(
		GetCurrentProcessToken(),
		TokenOwner,
		token_owner,
		sizeof(char) * 261,
		&dwRetSize
	);
	LPWSTR wszSIDPtr;
	ConvertSidToStringSid(token_owner->Owner, &wszSIDPtr);
	std::wcout << (WCHAR*)wszSIDPtr << std::endl;
	if(wszSIDPtr != nullptr)
		LocalFree(wszSIDPtr);
	return 0;
}