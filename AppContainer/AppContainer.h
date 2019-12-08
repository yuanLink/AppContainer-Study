#pragma once
#include "SelfWinNT.h"

SID_IDENTIFIER_AUTHORITY SIA_NT = SECURITY_NT_AUTHORITY;

NTSTATUS WINAPI BuildAppContainerSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR ExistingSecurityDescriptor,
	_In_ PSID SandBoxSid,
	_In_ PSID UserSid,
	_In_ bool IsRpcControl,
	_Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor);