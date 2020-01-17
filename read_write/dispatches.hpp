#pragma once
#include "main.hpp"

static PDRIVER_DISPATCH original_irp{};

NTSTATUS control(PDEVICE_OBJECT device_object, PIRP irp_call) {
	const auto stack = IoGetCurrentIrpStackLocation(irp_call);
	
	if (!original_irp)
		return STATUS_INTERNAL_ERROR;

	if (!irp_call->AssociatedIrp.SystemBuffer)
		return STATUS_INVALID_PARAMETER;

	auto bytes_operated = 0ul;
	auto operation_status = STATUS_SUCCESS;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
	case copy_memory_ioctl:
	{
		auto request = reinterpret_cast<memory_request*>(irp_call->AssociatedIrp.SystemBuffer);

		if (!request->virtual_address) {
			operation_status = STATUS_INVALID_PARAMETER;
			break;
		}
		
		const auto process = win::attain_process(request->process_id);

		if (!process) {
			operation_status = STATUS_INVALID_PARAMETER;
			break;
		}

		KAPC_STATE apc{};
		
		KeStackAttachProcess(process.get(), &apc);
		
		MEMORY_BASIC_INFORMATION info{};

		operation_status = ZwQueryVirtualMemory(ZwCurrentProcess(), reinterpret_cast<void*>(request->virtual_address), MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), nullptr);

		if (!NT_SUCCESS(operation_status)) {
			operation_status = STATUS_INVALID_PARAMETER;
			KeUnstackDetachProcess(&apc);
			break;
		}

		constexpr auto flags = PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE;
		constexpr auto page = PAGE_GUARD | PAGE_NOACCESS;

		if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
			operation_status = STATUS_ACCESS_DENIED;
			KeUnstackDetachProcess(&apc);
			break;
		}

		request->memory_state ?
			memcpy(reinterpret_cast<void*>(request->virtual_address), reinterpret_cast<void*>(request->memory_buffer), request->memory_size)
			:
			memcpy(reinterpret_cast<void*>(request->memory_buffer), reinterpret_cast<void*>(request->virtual_address), request->memory_size);

		request->memory_state ? 
			print("[uc_driver.sys] copied 0x%llx to 0x%llx\n", request->memory_buffer, request->virtual_address)
			:
			print("[uc_driver.sys] copied 0x%llx to 0x%llx\n", request->virtual_address, request->memory_buffer);
		
		KeUnstackDetachProcess(&apc);

		bytes_operated = sizeof(memory_request);
		operation_status = STATUS_SUCCESS;
		break;
	}
	case main_module_ioctl: {
		auto request = reinterpret_cast<module_request*>(irp_call->AssociatedIrp.SystemBuffer);

		const auto process = win::attain_process(request->process_id);

		if (!process) {
			operation_status = STATUS_INVALID_PARAMETER;
			break;
		}

		request->memory_buffer = reinterpret_cast<std::uintptr_t>(win::PsGetProcessSectionBaseAddress(process.get()));

		bytes_operated = sizeof(module_request);
		operation_status = STATUS_SUCCESS;
		break;
	}
	default:
		return original_irp(device_object, irp_call);
	}

	irp_call->IoStatus.Information = bytes_operated;
	irp_call->IoStatus.Status = operation_status;
	IofCompleteRequest(irp_call, 0);

	return STATUS_SUCCESS;
}
