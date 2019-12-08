#include"AppContainer.h"

#define CHECKRTL \
if (!NT_SUCCESS(status)) { \
	std::cout << "Error with error code " << std::hex << status << std::endl;\
	goto END; \
}

SID_IDENTIFIER_AUTHORITY SIA_NT = SECURITY_NT_AUTHORITY;

extern decltype(RtlAllocateAndInitializeSid) *PFNRtlAllocateAndInitializeSid;
extern decltype(RtlFreeSid) *PFNRtlFreeSid;

NTSTATUS WINAPI BuildAppContainerSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR ExistingSecurityDescriptor,
	_In_ PSID SandBoxSid,
	_In_ PSID UserSid,
	_In_ bool IsRpcControl,
	_Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor) {

	NTSTATUS status = 0;
	DWORD dwRetLength = 0;
	bool DaclPresent = false;
	bool DAclDefaulted = false;
	PACL pAcl = nullptr, pNewAcl = nullptr;
	PSID pAdminSID = nullptr, pRestrictedSid = nullptr, pWorldSid = nullptr;
	bool bUserSIDExit = false;
	PACCESS_ALLOWED_ACE pTempACE = nullptr;

	// initialize restricted sid
	status = PFNRtlAllocateAndInitializeSid(
		&SIA_NT, 1, SECURITY_RESTRICTED_CODE_RID,
		0, 0, 0, 0, 0, 0, 0, &pRestrictedSid);
	/*if (!NT_SUCCESS(status)) {
		std::cout << "Error with error code " << std::hex << status << std::endl;
	}*/
	CHECKRTL
	// initialize admin sid
	status = PFNRtlAllocateAndInitializeSid(
		&SIA_NT, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdminSID);

	//if (!NT_SUCCESS(status)) {
	//	std::cout << "Error with error code " << std::hex << status << std::endl;
	//}
	CHECKRTL
	// initilaize every one sid
	status = PFNRtlAllocateAndInitializeSid(
		&SIA_NT, 1, SECURITY_WORLD_RID,
		0, 0, 0, 0, 0, 0, 0, &pWorldSid);
	CHECKRTL

		
END:
	PFNRtlFreeSid(pWorldSid);
	PFNRtlFreeSid(pAdminSID);
	PFNRtlFreeSid(pRestrictedSid);
	return false;
}