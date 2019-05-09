#pragma once
#include "win.hpp"
#include <algorithm>
#include <string_view>
#include <array>

namespace memory {
	std::pair<std::uintptr_t, std::size_t> kernel_module;

	bool init() {
		auto loaded_modules = *reinterpret_cast<std::uintptr_t*>(win::PsLoadedModuleList);

		if (!loaded_modules)
			return false;

		kernel_module = { static_cast<std::uintptr_t>(loaded_modules + 0x30), static_cast<std::size_t>(loaded_modules + 0x40) };

		return kernel_module.second != 0;
	}

	/* drew :flushed: */
	template <std::size_t pattern_length> std::uintptr_t from_pattern(const char(&sig)[pattern_length], const char(&mask)[pattern_length]) {
		auto pattern_view = std::string_view{ reinterpret_cast<char*>(kernel_module.first), kernel_module.second };
		std::array<std::pair<char, char>, pattern_length - 1> pattern{};

		for (std::size_t index = 0; index < pattern_length - 1; index++)
			pattern[index] = { sig[index], mask[index] };

		auto resultant_address = std::search(pattern_view.cbegin(),
			pattern_view.cend(),
			pattern.cbegin(),
			pattern.cend(),
			[](char left, std::pair<char, char> right) -> bool {
				return (right.second == '?' || left == right.first);
			});

		return resultant_address == pattern_view.cend() ? 0 : reinterpret_cast<std::uintptr_t>(resultant_address.operator->());
	}
}
