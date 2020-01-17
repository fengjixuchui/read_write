#pragma once
#include "memory.hpp"
#include <string>

#define print(text, ...) DbgPrintEx(77, 0, text, ##__VA_ARGS__)

namespace clean {
	bool ldr_table(const wchar_t* device) {
		UNICODE_STRING driver_name = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
		PDRIVER_OBJECT driver_object = nullptr;

		win::ObReferenceObjectByName(&driver_name, 0, 0, 0, *win::IoDriverObjectType, KernelMode, nullptr, reinterpret_cast<void**>(&driver_object));

		if (!driver_object)
			return false;

		ObfDereferenceObject(driver_object);

		PLDR_DATA_TABLE_ENTRY begin = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(driver_object->DriverSection);

		auto current_module = begin;

		do
		{
			if (wcsncmp(current_module->BaseDllName.Buffer, device, wcslen(device)) == 0)
			{
				current_module->BaseDllName.MaximumLength = 0;
				return true;
			}

			current_module = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(current_module->InLoadOrderLinks.Flink);
		} while (current_module != begin);

		return true;
	}
	bool cache(const wchar_t* driver, const ULONG time_stamp) {
		auto resolve_rip = [](std::uintptr_t address) -> std::uintptr_t {
			if (!address)
				return 0;

			return address + *reinterpret_cast<std::int32_t*>(address + 3) + 7;
		};

		auto PiDDBCacheTable = reinterpret_cast<PRTL_AVL_TABLE>(resolve_rip(memory::from_pattern("\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83", "xxx????x????x????xx")));

		if (!PiDDBCacheTable)
			return false;
		
		auto PiDDBLock = reinterpret_cast<PERESOURCE>(resolve_rip(memory::from_pattern("\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x48\x8b\x0d\x00\x00\x00\x00\x33\xdb", "xxx????x????xxx????xx")));

		if (!PiDDBLock)
			return false;

		print("[uc_driver.sys] found PiDDBCacheTable at 0x%p\n", PiDDBCacheTable);
		print("[uc_driver.sys] found PiDDBLock at 0x%p\n", PiDDBLock);

		UNICODE_STRING driver_name = RTL_CONSTANT_STRING(driver); // change the name here to the driver you used to map this.

		PiDDBCacheEntry search_entry{};
		search_entry.DriverName = driver_name;
		search_entry.TimeDateStamp = time_stamp; // change the timestamp to the timestamp of the vulnerable driver used, get this using CFF Explorer or any PE editor

		ExAcquireResourceExclusiveLite(PiDDBLock, true);

		auto result = reinterpret_cast<PiDDBCacheEntry*>(RtlLookupElementGenericTableAvl(PiDDBCacheTable, &search_entry));

		if (!result) {
			ExReleaseResourceLite(PiDDBLock);
			return false;
		}

		print("[uc_driver.sys] found %wZ at 0x%p\n", &driver_name, result);


		RemoveEntryList(&result->List);
		RtlDeleteElementGenericTableAvl(PiDDBCacheTable, result);
		ExReleaseResourceLite(PiDDBLock);

		return true;
	}
}
