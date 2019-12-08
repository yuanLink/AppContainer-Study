#pragma once

#include <windows.h>
#include <iostream>
#include <winternl.h>

//
//typedef struct _UNICODE_STRING
//	{
//		WORD Length;
//		WORD MaximumLength;
//		WORD * Buffer;
//} UNICODE_STRING, *PUNICODE_STRING;
//typedef struct _OBJECT_ATTRIBUTES
//{
//	ULONG Length;
//	PVOID RootDirectory;
//	PUNICODE_STRING ObjectName;
//	ULONG Attributes;
//	PVOID SecurityDescriptor;
//	PVOID SecurityQualityOfService;
//} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
//typedef struct _LOWBOX_DATA
//{
//	HANDLE hAppContainerDir; // + 0x00 - Handle to "\Sessions\<ID>\AppContainerNamedObjects\<AppContSid>" Directory
//	HANDLE hAppContainerRpcDir;  // + 0x08 - Handle to "RPC Control" AppContainer directory
//	HANDLE hLocalSymLink; // + 0x10 - Handle to "Local" AppContainer Symbolic link object
//	HANDLE hGlobalSymLink; // + 0x18 - Handle to "Global" AppContainer Symbolic link object
//	HANDLE hSessionSymLink; // + 0x20 - Handle to "Session" AppContainer Symbolic link object
//	HANDLE hAppContNamedPipe; // + 0x28 - Handle to this App Container named pipe
//} LOWBOX_DATA, *PLOWBOX_DATA;

#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS STANDARD_RIGHTS_REQUIRED | 0xF

NTSTATUS
NTAPI
NtOpenDirectoryObject(
		OUT PHANDLE             DirectoryObjectHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes
	);

//
 NTSTATUS NTAPI NtQueryInformationToken(
	IN HANDLE               TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID               TokenInformation,
	IN ULONG                TokenInformationLength,
	OUT PULONG              ReturnLength);

 NTSTATUS NTAPI NtQuerySecurityObject(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG                Length,
	PULONG               LengthNeeded
);

NTSTATUS NTAPI NtCreateLowBoxToken(
	PHANDLE LowBoxTokenHandle,
	HANDLE TokenHandle,
	ACCESS_MASK DesiredAccess,
	OBJECT_ATTRIBUTES * ObjectAttributes,
	PSID PackageSid,
	ULONG CapabilityCount,
	PSID_AND_ATTRIBUTES Capabilities,
	ULONG HandleCount,
	PHANDLE Handles
);

/*
Routine Description:

	This function allocates and initializes a sid with the specified
	number of sub-authorities (up to 8).  A sid allocated with this
	routine must be freed using RtlFreeSid().

	THIS ROUTINE IS CURRENTLY NOT CALLABLE FROM KERNEL MODE.

Arguments:

	IdentifierAuthority - Pointer to the Identifier Authority value to
		set in the SID.

	SubAuthorityCount - The number of sub-authorities to place in the SID.
		This also identifies how many of the SubAuthorityN parameters
		have meaningful values.  This must contain a value from 0 through
		8.

	SubAuthority0-7 - Provides the corresponding sub-authority value to
		place in the SID.  For example, a SubAuthorityCount value of 3
		indicates that SubAuthority0, SubAuthority1, and SubAuthority0
		have meaningful values and the rest are to be ignored.

	Sid - Receives a pointer to the SID data structure to initialize.

Return Value:

	STATUS_SUCCESS - The SID has been allocated and initialized.

	STATUS_NO_MEMORY - The attempt to allocate memory for the SID
		failed.

	STATUS_INVALID_SID - The number of sub-authorities specified did
		not fall in the valid range for this api (0 through 8).
*/
NTSYSAPI NTSTATUS NTAPI RtlAllocateAndInitializeSid(
	PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
	UCHAR                     SubAuthorityCount,
	ULONG                     SubAuthority0,
	ULONG                     SubAuthority1,
	ULONG                     SubAuthority2,
	ULONG                     SubAuthority3,
	ULONG                     SubAuthority4,
	ULONG                     SubAuthority5,
	ULONG                     SubAuthority6,
	ULONG                     SubAuthority7,
	PSID                      *Sid
);

NTSYSAPI PVOID NTAPI RtlFreeSid(
	PSID Sid
);
//NTSTATUS RtlConvertSidToUnicodeString(
//	PUNICODE_STRING UnicodeString,
//	PSID            Sid,
//	BOOLEAN         AllocateDestinationString
//);
//
//void RtlInitUnicodeString(
//	PUNICODE_STRING DestinationString,
//	PCWSTR          SourceString
//);

template<typename FUNCNAME>
FUNCNAME SelfGetProcAddress(HMODULE hModule, const char* dwFuncName) {
	auto PFNProc = reinterpret_cast<FUNCNAME>(GetProcAddress(hModule, dwFuncName));
	if (PFNProc == nullptr) {
		std::cout << "Get Function failed:" << dwFuncName << "Error code" << std::hex << GetLastError() <<std::endl;
		return nullptr;
	}
	return PFNProc;
}