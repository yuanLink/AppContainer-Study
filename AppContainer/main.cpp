#include "SelfWinNT.h"
#include "AppContainer.h"
#include <strsafe.h>
#include <sddl.h>
#include <UserEnv.h>

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
decltype(RtlAllocateAndInitializeSid) *PFNRtlAllocateAndInitializeSid;
decltype(RtlFreeSid) *PFNRtlFreeSid;

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
	PFNRtlAllocateAndInitializeSid = SelfGetProcAddress<decltype(RtlAllocateAndInitializeSid)*>(hNtdll, "RtlAllocateAndInitializeSid");
	PFNRtlFreeSid = SelfGetProcAddress<decltype(RtlFreeSid)*>(hNtdll, "RtlFreeSid");
	if (!PFNNtOpenDirectoryObject ||
		!PFNNtQueryInformationToken ||
		!PFNNtQuerySecurityObject ||
		!PFNRtlConvertSidToUnicodeString ||
		!PFNRtlInitUnicodeString || 
		!PFNRtlAllocateAndInitializeSid || 
		!PFNRtlFreeSid)
		return false;
	return true;
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
	UNICODE_STRING usAppContainerSID, usBNO;
	WCHAR Buffer[MAX_PATH] = { 0 };
	OBJECT_ATTRIBUTES ObjAttr;
	HANDLE hBaseNamedObjects;
	PTOKEN_USER pUserTokenInfo = nullptr;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = nullptr;

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



CLEAN:
	if (pSecurityDescriptor != nullptr) {
		LocalFree(pSecurityDescriptor);
	}
	if (pUserTokenInfo != nullptr) {
		LocalFree(pUserTokenInfo);
	}
	return status;
}

WELL_KNOWN_SID_TYPE capabilitiyTypeList[] =
{
		WinCapabilityInternetClientSid,
		WinCapabilityInternetClientServerSid,
		WinCapabilityPrivateNetworkClientServerSid,
};

int main() {

	if (!InitEssantialFunciton()) {
		return -1;
	}
	HANDLE hLowBoxToken;
	HANDLE hCPHandle = GetCurrentProcessToken();
	SECURITY_CAPABILITIES SecurityCapabilities;
	SID_AND_ATTRIBUTES CapabilitiesList[10];
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

	WCHAR wszAppContainerName[] = L"TestLowBox";
	PSID pAppContainerSID = nullptr;
	DWORD retValue = 0;
	retValue = CreateAppContainerProfile(
		wszAppContainerName,
		wszAppContainerName,
		wszAppContainerName,
		NULL, 0,
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
	SecurityCapabilities = { pAppContainerSID, CapabilitiesList, 10 ,0 };
	CreateSelfAppContainerToken(&hLowBoxToken, hCPHandle, &SecurityCapabilities);
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
	//return 0;
}