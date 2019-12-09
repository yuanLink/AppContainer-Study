#pragma once
#include "SelfWinNT.h"

typedef enum _TOKEN_INTEGRITY_LEVELS_LIST
{
	// S-1-16-0
	UntrustedLevel = SECURITY_MANDATORY_UNTRUSTED_RID,

	// S-1-16-4096
	LowLevel = SECURITY_MANDATORY_LOW_RID,

	// S-1-16-8192
	MediumLevel = SECURITY_MANDATORY_MEDIUM_RID,

	// S-1-16-8448
	MediumPlusLevel = SECURITY_MANDATORY_MEDIUM_PLUS_RID,

	// S-1-16-12288
	HighLevel = SECURITY_MANDATORY_HIGH_RID,

	// S-1-16-16384
	SystemLevel = SECURITY_MANDATORY_SYSTEM_RID,

	// S-1-16-20480
	ProtectedLevel = SECURITY_MANDATORY_PROTECTED_PROCESS_RID
} TOKEN_INTEGRITY_LEVELS_LIST, *PTOKEN_INTEGRITY_LEVELS_LIST;

NTSTATUS WINAPI BuildAppContainerSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR ExistingSecurityDescriptor,
	_In_ PSID SandBoxSid,
	_In_ PSID UserSid,
	_In_ bool IsRpcControl,
	_Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor);

NTSTATUS WINAPI SetKernelObjectIntegrityLevel(
	_In_ HANDLE Object,
	_In_ TOKEN_INTEGRITY_LEVELS_LIST IL
);

bool WINAPI IsLogonSid(_In_ PSID pSid);

#define OBJECT_TYPE_CREATE 0x0001
#define OBJECT_TYPE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)