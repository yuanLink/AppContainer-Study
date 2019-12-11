#include"AppContainer.h"

#define CHECKRTL if (!NT_SUCCESS(status)) { std::cout << "Error with error code " << std::hex << status << std::endl;goto END; }

const SIZE_T SIA_Length = sizeof(SID_IDENTIFIER_AUTHORITY);
SID_IDENTIFIER_AUTHORITY SIA_NT = SECURITY_NT_AUTHORITY;
SID_IDENTIFIER_AUTHORITY SIA_IL = SECURITY_MANDATORY_LABEL_AUTHORITY;

extern decltype(RtlAllocateAndInitializeSid) *PFNRtlAllocateAndInitializeSid;
extern decltype(RtlFreeSid) *PFNRtlFreeSid;
extern decltype(RtlGetDaclSecurityDescriptor) *PFNRtlGetDaclSecurityDescriptor;
extern decltype(RtlLengthSid) *PFNRtlLengthSid;
extern decltype(RtlCreateAcl) *PFNRtlCreateAcl;
extern decltype(RtlGetAce) *PFNRtlGetAce;
extern decltype(RtlIdentifierAuthoritySid) *PFNRtlIdentifierAuthoritySid;
extern decltype(RtlSubAuthorityCountSid) *PFNRtlSubAuthorityCountSid;
extern decltype(RtlSubAuthoritySid) *PFNRtlSubAuthoritySid;
extern decltype(RtlEqualSid) *PFNRtlEqualSid;
extern decltype(RtlAddAce) *PFNRtlAddAce;
extern decltype(RtlAddAccessAllowedAce) *PFNRtlAddAccessAllowedAce;
extern decltype(RtlAddAccessAllowedAceEx) *PFNRtlAddAccessAllowedAceEx;
extern decltype(RtlCreateSecurityDescriptor) *PFNRtlCreateSecurityDescriptor;
extern decltype(RtlSetDaclSecurityDescriptor) *PFNRtlSetDaclSecurityDescriptor;
extern decltype(NtDuplicateObject) *PFNNtDuplicateObject;
extern decltype(RtlAddMandatoryAce) *PFNRtlAddMandatoryAce;
extern decltype(RtlSetSaclSecurityDescriptor) *PFNRtlSetSaclSecurityDescriptor;
extern decltype(NtSetSecurityObject) *PFNNtSetSecurityObject;
extern decltype(NtClose) *PFNNtClose;

bool WINAPI IsLogonSid(_In_ PSID pSid) {
	// Get PSID SID_IDENTIFIER_AUTHORITY
	PSID_IDENTIFIER_AUTHORITY pSidAuth = PFNRtlIdentifierAuthoritySid(pSid);

	// if not suitable for SID_IDENTIFIER_AUTHORITY, return false
	if (memcmp(pSidAuth, &SIA_NT, SIA_Length)) return false;

	// check if this SID belong to logon sid
	return (*PFNRtlSubAuthorityCountSid(pSid) == SECURITY_LOGON_IDS_RID_COUNT
		&& *PFNRtlSubAuthoritySid(pSid, 0) == SECURITY_LOGON_IDS_RID);
}

/*
 *			BuildAppContainerSecurityDescriptor
 * Build a AppContainer Security Descriptor with a existing Security Descriptor
 * @param ExistingSecurityDescriptor: a existing Security Descriptor. It would be the one that save the appcontainer
 * like "\\Sessions\\%ld\\BaseNamedObjects"
 * @param SandBoxSid: the sandbox sid. It should be a AppContainer SID from CreateAppContainerProfile
 * @param UserSid: now user token sid.
 * @param IsRpcControl: switch to the RPC Control, not essential
 * @param NewSecurityDescriptor: a point to new Security Descriptor
 *
 */
NTSTATUS WINAPI BuildAppContainerSecurityDescriptor(
	_In_ PSECURITY_DESCRIPTOR ExistingSecurityDescriptor,
	_In_ PSID SandBoxSid,
	_In_ PSID UserSid,
	_In_ bool IsRpcControl,
	_Out_ PSECURITY_DESCRIPTOR *NewSecurityDescriptor) {

	NTSTATUS status = 0;
	DWORD dwRetLength = 0;
	BOOLEAN DaclPresent = false;
	BOOLEAN DAclDefaulted = false;
	PACL pAcl = nullptr, pNewAcl = nullptr;
	PSID pAdminSID = nullptr, pRestrictedSid = nullptr, pWorldSid = nullptr;
	BOOLEAN bUserSIDExist = false;
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

	// get exist object acl
	status = PFNRtlGetDaclSecurityDescriptor(
		ExistingSecurityDescriptor, &DaclPresent, &pAcl, &DAclDefaulted);
	CHECKRTL

	// calculate new ACL size
	dwRetLength = pAcl->AclSize;
	dwRetLength += PFNRtlLengthSid(SandBoxSid);
	dwRetLength += PFNRtlLengthSid(UserSid);
	dwRetLength += PFNRtlLengthSid(pRestrictedSid);
	dwRetLength += PFNRtlLengthSid(pAdminSID);
	dwRetLength += PFNRtlLengthSid(pWorldSid);
	dwRetLength += sizeof(ACCESS_ALLOWED_ACE) * 7;

	// Allocate ACL
	pNewAcl = reinterpret_cast<PACL>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwRetLength));
	if (pNewAcl == nullptr) {
		std::cout << "Heap Alloc error " << std::endl;
		goto END;
	}
	// Create new ACL
	status = PFNRtlCreateAcl(pNewAcl, dwRetLength, pAcl->AclRevision);
	CHECKRTL

	// Copy ACE
	for (ULONG i = 0; NT_SUCCESS(PFNRtlGetAce(pAcl, i, (PVOID*)&pTempACE)); i++) {
		//check if it is logon sid
		if (IsLogonSid(&pTempACE->SidStart)
			// ??
			&& !(pTempACE->Header.AceFlags && INHERIT_ONLY_ACE)) {
			// allow it to visit all directory
			pTempACE->Mask = DIRECTORY_ALL_ACCESS;
		}
		//if not RPC handle, we don't need to add admin and everyone sid
		if (!IsRpcControl
			&& (PFNRtlEqualSid(&pTempACE->SidStart, pAdminSID)
				|| PFNRtlEqualSid(&pTempACE->SidStart, pRestrictedSid)
				|| PFNRtlEqualSid(&pTempACE->SidStart, pWorldSid)))
			continue;
		if (PFNRtlEqualSid(&pTempACE->SidStart, UserSid))
			bUserSIDExist = true;

		// add ACE for new ACL
		PFNRtlAddAce(pNewAcl, pAcl->AclRevision, 0,
			pTempACE, pTempACE->Header.AceSize);
	}

	// add sandbox ACE(directory) for new ACL
	// HERE IS THE ROOT CAUSE THAT GLOBAL EVENT OBJECT COULD NOT BE OPENED
	status = AddAccessAllowedAce(
		pNewAcl,
		pAcl->AclRevision,
		DIRECTORY_ALL_ACCESS,
		SandBoxSid
	);
	CHECKRTL

	// add sandbox ACE(inheritedNone) for new ACL
	status = PFNRtlAddAccessAllowedAceEx(
		pNewAcl,
		pAcl->AclRevision,
		OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
		GENERIC_ALL,
		SandBoxSid
	);
	CHECKRTL

	// if not user sid exist
	if (!bUserSIDExist) {
		status = PFNRtlAddAccessAllowedAce(
			pNewAcl,
			pAcl->AclRevision,
			DIRECTORY_ALL_ACCESS,
			UserSid
		);
		CHECKRTL

		status = PFNRtlAddAccessAllowedAceEx(
			pNewAcl,
			pAcl->AclRevision,
			OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
			GENERIC_ALL,
			UserSid
		);
		CHECKRTL
	}

	// if it's RPC Control
	if (IsRpcControl) {
		// add admin, restricted and everyone sid with inherit only sid
		status = PFNRtlAddAccessAllowedAceEx(
			pNewAcl,
			pAcl->AclRevision,
			OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
			GENERIC_ALL,
			pAdminSID
		);
		CHECKRTL
		status = PFNRtlAddAccessAllowedAceEx(
			pNewAcl,
			pAcl->AclRevision,
			OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
			GENERIC_READ | GENERIC_EXECUTE,
			pRestrictedSid
		);
		CHECKRTL
		status = PFNRtlAddAccessAllowedAceEx(
			pNewAcl,
			pAcl->AclRevision,
			OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
			GENERIC_READ | GENERIC_EXECUTE,
			pWorldSid
		);
	}
	
	// Allocate and create SID for AppContainer
	*NewSecurityDescriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECURITY_DESCRIPTOR)));

	status = PFNRtlCreateSecurityDescriptor(
		*NewSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	CHECKRTL
	status = PFNRtlSetDaclSecurityDescriptor(
		*NewSecurityDescriptor, DaclPresent, pNewAcl, DAclDefaulted
	);
	CHECKRTL
END:
	PFNRtlFreeSid(pWorldSid);
	PFNRtlFreeSid(pAdminSID);
	PFNRtlFreeSid(pRestrictedSid);
	return status;
}

#define CHECKKIL if (!NT_SUCCESS(status)) goto FuncEnd;
NTSTATUS WINAPI SetKernelObjectIntegrityLevel(
	_In_ HANDLE Object,
	_In_ TOKEN_INTEGRITY_LEVELS_LIST IL
) {
	const size_t AclLength = 88;
	NTSTATUS status = 0;
	PSID pSid = nullptr;
	PACL pAcl = nullptr;
	SECURITY_DESCRIPTOR sd;
	HANDLE hNewHandle = nullptr;

	//[TODO]:MAYBE HAVE SOME PROBLEM HERE
	status = PFNNtDuplicateObject(
		GetCurrentProcess(),
		Object,
		GetCurrentProcess(),
		&hNewHandle,
		DIRECTORY_ALL_ACCESS,
		0, 0
	);
	CHECKKIL

	// initialize Interity sid
	status = PFNRtlAllocateAndInitializeSid(
			&SIA_IL, 1, IL,
			0, 0, 0, 0, 0, 0, 0, &pSid);
	CHECKKIL
	pAcl = reinterpret_cast<PACL>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AclLength));
	if (pAcl == nullptr) {
		std::cout << "Create Heap error" << std::endl;
		goto FuncEnd;
	}

	status = PFNRtlCreateSecurityDescriptor(
		&sd, SECURITY_DESCRIPTOR_REVISION
	);
	CHECKKIL

	status = PFNRtlCreateAcl(
		pAcl, AclLength, ACL_REVISION
	);
	CHECKKIL

	// Add integrity level to ACL
	status = PFNRtlAddMandatoryAce(
		pAcl, ACL_REVISION, 0, pSid,
		SYSTEM_MANDATORY_LABEL_ACE_TYPE, OBJECT_TYPE_CREATE);
	CHECKKIL

	// set SACL
	status = PFNRtlSetSaclSecurityDescriptor(&sd, true, pAcl, false);
	CHECKKIL

	// set kernel security object
	status = PFNNtSetSecurityObject(
		hNewHandle, LABEL_SECURITY_INFORMATION, &sd);
	CHECKKIL

FuncEnd:
	HeapFree(GetProcessHeap(), NULL, pAcl);
	PFNRtlFreeSid(pSid);
	PFNNtClose(hNewHandle);

	return status;
}