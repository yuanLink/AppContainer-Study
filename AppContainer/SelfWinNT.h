#pragma once

#include<windows.h>
#include<iostream>
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

NTSYSAPI
NTSTATUS
NTAPI
NtOpenDirectoryObject(
		OUT PHANDLE             DirectoryObjectHandle,
		IN ACCESS_MASK          DesiredAccess,
		IN POBJECT_ATTRIBUTES   ObjectAttributes
	);

//
NTSYSAPI NTSTATUS NTAPI NtQueryInformationToken(
	IN HANDLE               TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID               TokenInformation,
	IN ULONG                TokenInformationLength,
	OUT PULONG              ReturnLength);

__kernel_entry NTSYSCALLAPI NTSTATUS NtQuerySecurityObject(
	HANDLE               Handle,
	SECURITY_INFORMATION SecurityInformation,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	ULONG                Length,
	PULONG               LengthNeeded
);

NTSTATUS NtCreateLowBoxToken(
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

template<typename FUNCNAME>
FUNCNAME SelfGetProcAddress(HMODULE hModule, const char* dwFuncName) {
	auto PFNProc = reinterpret_cast<FUNCNAME>(GetProcAddress(hModule, dwFuncName));
	if (PFNProc == nullptr) {
		std::cout << "Get Function failed:" << dwFuncName << "Error code" << std::hex << GetLastError() <<std::endl;
		return nullptr;
	}
	return PFNProc;
}