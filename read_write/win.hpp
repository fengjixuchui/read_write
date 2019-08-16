#pragma once
#include <memory>
#include <ntifs.h>

enum SYSTEM_INFORMATION_CLASS : std::uint32_t
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
};

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	// ...
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
};
struct memory_request {
	std::uintptr_t process_id;
	std::uintptr_t virtual_address;
	std::size_t memory_size;
	std::uintptr_t memory_buffer;
	bool memory_state; // true: write, false: read
};
struct module_request {
	std::uintptr_t process_id;
	std::uintptr_t memory_buffer;
};

#define copy_memory_ioctl CTL_CODE( FILE_DEVICE_UNKNOWN, 0x602, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )
#define main_module_ioctl CTL_CODE( FILE_DEVICE_UNKNOWN, 0x603, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS )

namespace win {
	using e_process = std::unique_ptr<std::remove_pointer_t<PEPROCESS>, decltype(&ObfDereferenceObject)>;

	e_process attain_process(const std::uintptr_t process_id) {
		PEPROCESS process{};
		PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &process);
		return e_process(process, &ObfDereferenceObject);
	}

	extern "C" __declspec(dllimport) PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
	extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
	extern "C" __declspec(dllimport) NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING, ULONG, PACCESS_STATE, ACCESS_MASK, POBJECT_TYPE, KPROCESSOR_MODE, PVOID OPTIONAL, PVOID*);
	extern "C" __declspec(dllimport) PLIST_ENTRY NTAPI PsLoadedModuleList;
	extern "C" __declspec(dllimport) POBJECT_TYPE* IoDriverObjectType;
}
