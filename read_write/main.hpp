#pragma once
#include "memory.hpp"
#include <string>

#define print(text, ...) DbgPrintEx(77, 0, text, ##__VA_ARGS__)

namespace clean {
	bool unloaded_drivers() {
		auto current_instruction = memory::from_pattern("\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

		if (!current_instruction)
			return false;

		auto MmUnloadedDrivers = current_instruction + *reinterpret_cast<std::int32_t*>(current_instruction + 3) + 7;

		if (!MmUnloadedDrivers)
			return false;
		
		print("[uc_driver.sys] found MmUnloadedDrivers at 0x%llx\n", MmUnloadedDrivers);

		auto empty_buffer = ExAllocatePoolWithTag(NonPagedPool, 0x7d0, 'dick');

		if (!empty_buffer)
			return false;

		memset(empty_buffer, 0, 0x7d0);

		*reinterpret_cast<std::uintptr_t*>(MmUnloadedDrivers) = reinterpret_cast<std::uintptr_t>(empty_buffer);

		ExFreePoolWithTag(*reinterpret_cast<void**>(MmUnloadedDrivers), 'dick');

		return true;
	}
	bool cache() {
		auto resolve_rip = [](std::uintptr_t address) -> std::uintptr_t {
			if (!address)
				return 0;

			return address + *reinterpret_cast<std::int32_t*>(address + 3) + 7;
		};

		auto PiDDBCacheTable = reinterpret_cast<PRTL_AVL_TABLE>(resolve_rip(memory::from_pattern("\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x01\x00\x00", "xxx????x????xxxxx")));

		if (!PiDDBCacheTable)
			return false;
		
		auto PiDDBLock = reinterpret_cast<PERESOURCE>(resolve_rip(memory::from_pattern("\x48\x8d\x0d\x00\x00\x00\x00\x48\x83\x25\x00\x00\x00\x00\x00\xe8\x00\x00\x00\x00", "xxx????xxx?????x????")));

		if (!PiDDBLock)
			return false;

		print("[uc_driver.sys] found PiDDBCacheTable at 0x%p\n", PiDDBCacheTable);
		print("[uc_driver.sys] found PiDDBLock at 0x%p\n", PiDDBLock);

		UNICODE_STRING driver_name = RTL_CONSTANT_STRING(L"capcom.sys"); // change the name here to the driver you used to map this.

		PiDDBCacheEntry search_entry{};
		search_entry.DriverName = driver_name;
		search_entry.TimeDateStamp = 0x57CD1415; // change the timestamp to the timestamp of the vulnerable driver used, get this using CFF Explorer or any PE editor

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
