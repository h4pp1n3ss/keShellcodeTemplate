# keShellcodeTemplate
Keystone Engine shellcode template

# Descriptin 

This python script uses keystone-engine to create asm instruction. 
Keystone is a lightweight multi-platform, multi-architecture assembler framework for more
information visit [site](https://www.keystone-engine.org/).

After create the desired instruction this script will Allocate space in memory, Move the encoded ASM
instruction to the new allocated space and CreateThread from this location, so basically is a shellcode runner

# Runner

The shellcode runner uses it classic invocation 

## VirtualAlloc function (memoryapi.h) 

[VirtualAlloc function info](https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)

```c 
LPVOID VirtualAlloc(
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
```


## RtlMoveMemory function

[RtlMoveMemory function info](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

```c 
VOID RtlMoveMemory(
  _Out_       VOID UNALIGNED *Destination,
  _In_  const VOID UNALIGNED *Source,
  _In_        SIZE_T         Length
);
```
## CreateThread function (processthreadsapi.h)

[CreateThread function info](https://docs.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory)

```c 
HANDLE CreateThread(
  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  SIZE_T                  dwStackSize,
  LPTHREAD_START_ROUTINE  lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD                   dwCreationFlags,
  LPDWORD                 lpThreadId
);
```
## WaitForSingleObject function (synchapi.h)

[WaitForSingleObject function info](https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)

```c 
DWORD WaitForSingleObject(
  HANDLE hHandle,
  DWORD  dwMilliseconds
);
```


# Credits / References

[Keystone-engine](https://www.keystone-engine.org/) The framework make things more easily.

[github-epi052](https://github.com/epi052) Good job automating functions.

[Offsec](https://www.offensive-security.com/) Amazing shellcode development course.