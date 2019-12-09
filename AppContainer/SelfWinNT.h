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

#define SYMBOLIC_LINK_QUERY 0x0001
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

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

 NTSYSAPI NTSTATUS NTAPI RtlGetDaclSecurityDescriptor(
	 PSECURITY_DESCRIPTOR SecurityDescriptor,
	 PBOOLEAN             DaclPresent,
	 PACL                 *Dacl,
	 PBOOLEAN             DaclDefaulted
 );

NTSYSAPI ULONG NTAPI RtlLengthSid(
	 PSID Sid
 );

NTSYSAPI NTSTATUS NTAPI RtlCreateAcl(
	PACL  Acl,
	ULONG AclLength,
	ULONG AclRevision
);

NTSYSAPI NTSTATUS NTAPI RtlGetAce(
	PACL  Acl,
	ULONG AceIndex,
	PVOID *Ace
);

NTSYSAPI PSID_IDENTIFIER_AUTHORITY NTAPI RtlIdentifierAuthoritySid(
	PSID Sid
);

NTSYSAPI PUCHAR NTAPI RtlSubAuthorityCountSid(
	PSID Sid
);

NTSYSAPI PULONG NTAPI RtlSubAuthoritySid(
	PSID  Sid,
	ULONG SubAuthority
);

NTSYSAPI BOOLEAN NTAPI RtlEqualSid(
	PSID Sid1,
	PSID Sid2
);

NTSYSAPI NTSTATUS NTAPI RtlAddAce(
	PACL  Acl,
	ULONG AceRevision,
	ULONG StartingAceIndex,
	PVOID AceList,
	ULONG AceListLength
);

NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAce(
	PACL        Acl,
	ULONG       AceRevision,
	ACCESS_MASK AccessMask,
	PSID        Sid
);

NTSYSAPI NTSTATUS NTAPI RtlAddAccessAllowedAceEx(
	PACL        Acl,
	ULONG       AceRevision,
	ULONG       AceFlags,
	ACCESS_MASK AccessMask,
	PSID        Sid
);

NTSYSAPI NTSTATUS NTAPI RtlCreateSecurityDescriptor(
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG                Revision
);

NTSYSAPI NTSTATUS NTAPI RtlSetDaclSecurityDescriptor(
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN              DaclPresent,
	PACL                 Dacl,
	BOOLEAN              DaclDefaulted
);

#if (PHNT_VERSION >= PHNT_WIN8)
NTSTATUS
NTAPI
NtCreateDirectoryObjectEx(
	_Out_ PHANDLE DirectoryHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ShadowDirectoryHandle,
	_In_ ULONG Flags
);
#endif

NTSTATUS NTAPI NtDuplicateObject(
	HANDLE      SourceProcessHandle,
	HANDLE      SourceHandle,
	HANDLE      TargetProcessHandle,
	PHANDLE     TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG       HandleAttributes,
	ULONG       Options
);

NTSTATUS NTAPI 	RtlAddMandatoryAce(
	_Inout_ PACL Acl,
	_In_ ULONG AceRevision,
	_In_ ULONG AceFlags,
	_In_ PSID Sid,
	_In_ UCHAR AceType,
	_In_ ACCESS_MASK AccessMask
);

NTSTATUS NTAPI RtlSetSaclSecurityDescriptor(
	_Inout_ PSECURITY_DESCRIPTOR 	SecurityDescriptor,
	_In_ BOOLEAN 	SaclPresent,
	_In_opt_ PACL 	Sacl,
	_In_opt_ BOOLEAN 	SaclDefaulted
);

NTSTATUS NTAPI NtSetSecurityObject(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor
);

NTSTATUS NTAPI NtClose(
	IN HANDLE Handle
);

NTSTATUS NTAPI NtCreateSymbolicLinkObject(
	OUT PHANDLE             pHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes,
	IN PUNICODE_STRING      DestinationName
);

NTSTATUS NTAPI NtCreateLowBoxToken(
	_Out_ PHANDLE TokenHandle,
	_In_ HANDLE ExistingTokenHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ PSID PackageSid,
	_In_ ULONG CapabilityCount,
	_In_reads_opt_(CapabilityCount) PSID_AND_ATTRIBUTES Capabilities,
	_In_ ULONG HandleCount,
	_In_reads_opt_(HandleCount) HANDLE *Handles
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
