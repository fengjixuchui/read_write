#pragma once
#include "win.hpp"
#include <algorithm>
#include <string_view>
#include <array>

namespace memory {
	std::pair<std::uintptr_t, std::size_t> kernel_module;

	bool init() {
		auto loaded_modules = reinterpret_cast<std::uintptr_t>(win::PsLoadedModuleList);

		if (!loaded_modules)
			return false;

		kernel_module = { *reinterpret_cast<std::uintptr_t*>(loaded_modules + 0x30), *reinterpret_cast<std::size_t*>(loaded_modules + 0x40) };

		return kernel_module.second != 0;
	}

	std::uintptr_t from_pattern(const char* sig, const char* mask) {
		for (std::uintptr_t i = 0; i < kernel_module.second; i++)
			if ([](std::uint8_t const* data, std::uint8_t const* sig, char const* mask) {
				for (; *mask; ++mask, ++data, ++sig) {
					if (*mask == 'x' && *data != *sig) return false;
				}
				return (*mask) == 0;
				}((std::uint8_t*)(kernel_module.first + i), (std::uint8_t*)sig, mask))
					return kernel_module.first + i;

		return 0;
	}
}
