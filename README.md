# AppContainer Study note

这是一篇学习 Windows AppContainer的笔记，基本上是搬运[https://github.com/M2Team/M2TeamCommonLibrary](https://github.com/M2Team/M2TeamCommonLibrary)的代码。仅作为个人笔记使用。。。。

## 学习目标

弄清楚代码中的逻辑，并且实现修改AppContainer的权限

### CHAPTER0 CREATE APPCONTAINER SELF
Q:
为什么要大费周章的使用`NtCreateLowBoxToken`？使用`CreateAppContainerProfile`明明已经能够创建AppContainer了。如果说真的是从头开始创建的话，为什么这边又需要一个`AppContainer SID`呢？

Q:
整个创建流程做了些什么呢？

Q: AppContainer的进程的特征在哪儿？具体的进程Token和普通的进程Token的区别是啥？

Q: 如何查看具体的进程Token  
A: 
user-mode:
使用windbg调试指定进程，然后键入
```
!token
```
kernel-mode:
使用windbg调试（可以lkd），然后用
```
!process 0 0 <name>
```
找到进程信息
```
lkd> !process 0 0 Calculator.exe
PROCESS ffff9c0cd4b7d080
    SessionId: 1  Cid: 31c4    Peb: 24d7912000  ParentCid: 028c
    DirBase: 23ac00002  ObjectTable: ffffae07b1259700  HandleCount: 525.
    Image: Calculator.exe

```
然后继续用这个指令，打印进程详细信息:
```
!process PROCESS-address 1

lkd> !process ffff9c0cd4b7d080 1
PROCESS ffff9c0cd4b7d080
    SessionId: 1  Cid: 31c4    Peb: 24d7912000  ParentCid: 028c
    DirBase: 23ac00002  ObjectTable: ffffae07b1259700  HandleCount: 509.
    Image: Calculator.exe
    VadRoot ffff9c0cd372a750 Vads 214 Clone 0 Private 4330. Modified 4267. Locked 1554.
    DeviceMap ffffae07ae54e550
    Token                             ffffae07a6184050
    ElapsedTime                       18:23:18.156
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         683544
    QuotaPoolUsage[NonPagedPool]      29552
    Working Set Sizes (now,min,max)  (14175, 50, 345) (56700KB, 200KB, 1380KB)
    PeakWorkingSetSize                14813
    VirtualSize                       445 Mb
    PeakVirtualSize                   453 Mb
    PageFaultCount                    22835
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      5411
    Job                               ffff9c0cd452a830
```
找到token之后，就可以用
```
dt nt!_token
```
进行查看:
```

lkd> dt nt!_token ffffae07a6184050
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x030 TokenLock        : 0xffff9c0c`d0ee9450 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   +0x058 AuditPolicy      : _SEP_AUDIT_POLICY
   +0x078 SessionId        : 1
   +0x07c UserAndGroupCount : 0x7c
   +0x080 RestrictedSidCount : 0
   +0x084 VariableLength   : 0x14a8
   +0x088 DynamicCharged   : 0x1000
   +0x08c DynamicAvailable : 0
   +0x090 DefaultOwnerIndex : 0
   +0x098 UserAndGroups    : 0xffffae07`a61844e0 _SID_AND_ATTRIBUTES
   +0x0a0 RestrictedSids   : (null) 
   +0x0a8 PrimaryGroup     : 0xffffae07`9ec4b360 Void
   +0x0b0 DynamicPart      : 0xffffae07`9ec4b360  -> 0x501
   +0x0b8 DefaultDacl      : 0xffffae07`9ec4b37c _ACL
   +0x0c0 TokenType        : 1 ( TokenPrimary )
   +0x0c4 ImpersonationLevel : 0 ( SecurityAnonymous )
   +0x0c8 TokenFlags       : 0x4a00
   +0x0cc TokenInUse       : 0x1 ''
   +0x0d0 IntegrityLevelIndex : 0x7b
   +0x0d4 MandatoryPolicy  : 1
   +0x0d8 LogonSession     : 0xffffae07`a401a6e0 _SEP_LOGON_SESSION_REFERENCES
   +0x0e0 OriginatingLogonSession : _LUID
   +0x0e8 SidHash          : _SID_AND_ATTRIBUTES_HASH
   +0x1f8 RestrictedSidHash : _SID_AND_ATTRIBUTES_HASH
   +0x308 pSecurityAttributes : 0xffffae07`ae5431f0 _AUTHZBASEP_SECURITY_ATTRIBUTES_INFORMATION
   +0x310 Package          : 0xffffae07`b0b64300 Void
   +0x318 Capabilities     : 0xffffae07`abbdb850 _SID_AND_ATTRIBUTES
   +0x320 CapabilityCount  : 3
   +0x328 CapabilitiesHash : _SID_AND_ATTRIBUTES_HASH
   +0x438 LowboxNumberEntry : 0xffffae07`aafd31f0 _SEP_LOWBOX_NUMBER_ENTRY
   +0x440 LowboxHandlesEntry : 0xffffae07`9b61d230 _SEP_CACHED_HANDLES_ENTRY
   +0x448 pClaimAttributes : (null) 
   +0x450 TrustLevelSid    : (null) 
   +0x458 TrustLinkedToken : (null) 
   +0x460 IntegrityLevelSidValue : (null) 
   +0x468 TokenSidValues   : (null) 
   +0x470 IndexEntry       : 0xffffae07`9436dd80 _SEP_LUID_TO_INDEX_MAP_ENTRY
   +0x478 DiagnosticInfo   : (null) 
   +0x480 BnoIsolationHandlesEntry : (null) 
   +0x488 SessionObject    : 0xffff9c0c`cbddc670 Void
   +0x490 VariablePart     : 0xffffae07`a6184ca0
```

Q: 如何确定HANDLE对应的对象到底是啥呢？  
A: 在[自己的博客](http://showlinkroom.me/2019/04/26/Windows-Via-C-C-note-3/)有提到。这边再记录一下：
首先我们随便找一个进程距离，找到一个进程的句柄:
```
1: kd> !handle 94
PROCESS aed07600  SessionId: 1  Cid: 1b90    Peb: 00451000  ParentCid: 0d24
    DirBase: 3ffd35c0  ObjectTable: af3f4540  HandleCount:  38.
    Image: Exploit.exe
Handle table at af3f4540 with 38 entries in use
0094: Object: aed07600  GrantedAccess: 00001400 Entry: 8b83a128
Object: aed07600  Type: (8639b480) Process
    ObjectHeader: aed075e8 (new version)
        HandleCount: 7  PointerCount: 217
```
这个句柄94表示的是一个叫做Exploit.exe进程的进程对象。
```
0094: Object: aed07600  GrantedAccess: 00001400 Entry: 8b83a128
Object: aed07600  Type: (8639b480) Process
    ObjectHeader: aed075e8 (new version)
                     ^
                     |
        这里正是这个对象（object）在内存中的位置
        HandleCount: 7  PointerCount: 217
```
如果我们需要观察这个对象的话，只需要键入:
```
1: kd> dt _Object_header aed075e8
nt!_OBJECT_HEADER
   +0x000 PointerCount     : 0n217
   +0x004 HandleCount      : 0n7
   +0x004 NextToFree       : 0x00000007 Void
   +0x008 Lock             : _EX_PUSH_LOCK
   +0x00c TypeIndex        : 0xe1 ''
   +0x00d TraceFlags       : 0 ''
   +0x00d DbgRefTrace      : 0y0
   +0x00d DbgTracePermanent : 0y0
   +0x00e InfoMask         : 0x88 ''
   +0x00f Flags            : 0 ''
   +0x00f NewObject        : 0y0
   +0x00f KernelObject     : 0y0
   +0x00f KernelOnlyAccess : 0y0
   +0x00f ExclusiveObject  : 0y0
   +0x00f PermanentObject  : 0y0
   +0x00f DefaultSecurityQuota : 0y0
   +0x00f SingleHandleEntry : 0y0
   +0x00f DeletedInline    : 0y0
   +0x010 ObjectCreateInfo : 0x8d2952c0 _OBJECT_CREATE_INFORMATION
   +0x010 QuotaBlockCharged : 0x8d2952c0 Void
   +0x014 SecurityDescriptor : 0xa7a77596 Void
   +0x018 Body             : _QUAD
```
并且用户态是可以查询到这个地址的，通过调用神奇API`NtQuerySystemInformation`里面的`SystemHandleInformation`即可查询到
### CHAPTER1 LIMIT ACCESS FOR GLOBAL OBJECT
Q:
一个APPContainer进程能够访问的全局对象是有限的？这是怎么回事？

Senario:
> Chrome Beta 78 render 进程

A:
据观察，在创建AppContainer的token的时候，需要调用API
```cpp
NTSTATUS NtCreateLowBoxToken(
    HANDLE * phLowBoxToken, 
    HANDLE hOrgToken, 
    ACCESS_MASK DesiredAccess, 
    OBJECT_ATTRIBUTES * pOa, 
    PSID pAppContainerSid, 
    DWORD capabilityCount, 
    PSID_AND_ATTRIBUTES capabilities, 
    DWORD lowBoxStructHandleCount, 
    PLOWBOX_DATA lowBoxStruct
    );
```
这个API会创建一个`LowBox Token`，这个token 是一个低权限的token，可以作为`primary user token`使用。在`CreateProcessAsUser`的时候可以使用，从而创建一个创建受到限制的进程（也就是APPContainer）。

Q: 不能访问全局的原因找到了，是因为创建Root Directory的时候，没有带有任何安全描述符。创建对象的时候没有安全描述符会发生什么呢？  
A: 这个似乎找到答案了。对于通常的进程来说，一个`NULL`的DACL意味着**任意访问权限**，而对于AppContainer进程来说，这就意味着**全部Deny**。换句话说，AppContainer进程中**只有显示定义了Allow的权限才能够被允许执行**。

Q: 那具体是哪个安全描述符导致的问题呢？  
目前已近确定了，是`\\Sessions\{sessionID}\AppContainerNamedObjects\{AppContainerSID}`这个对象下的**PACKAGE SID**这个Owner的以下几个权限没有出现  
![Owner](./img/img00.png)  
![权限](./img/img01.png)  
当如上带有tick的权限的都没有的时候，可以理解成当前进程，也就是**PACKAGE SID**的token对于`Add Object\list\Add Subdirectory`会没有权限，于是AppContainer的进程就会在打开Object的时候，出现`OpenEvent failed`。
_猜测理由：因为没有`Add Object`的话，可能_


## TODOList

 * [x] BuildAppContainerSecurityDescriptor的完成
 * [x] SetKernelObjectIntegrityLevel的完成
 * [x] NtCreateSymbolicLinkObject的使用（指不创建global link)
 * [x] 对进程中AppContainer SID修改的研究
 * [ ] 跨进程对AppContainer SID修改的研究
 * [ ] 使用`Impersonate`尝试访问Object

