// SPDX-License-Identifier: BSD-3

// Truncated Thumb instructions at the end of the input buffer. The first
// halfword of a 32-bit Thumb-2 encoding selects the instruction length, so
// a buffer ending after that halfword must fail without reading past it.

#include "truncated_input.h"

// 2d e9 f0 41    push.w {r4, r5, r6, r7, r8, lr} (32-bit encoding)
static const uint8_t code_push_w[] = { 0x2d, 0xe9, 0xf0, 0x41 };
// 00 bf          nop (16-bit), then the 32-bit push.w above
static const uint8_t code_nop_push_w[] = { 0x00, 0xbf, 0x2d, 0xe9, 0xf0, 0x41 };

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) != CS_ERR_OK) {
		printf("cs_open failed\n");
		return -1;
	}
	bool ok = true;

	static const size_t push_w_consumed[] = { 0, 0, 0, 4 };
	ok &= check_truncations(handle, "push_w", code_push_w,
				sizeof(code_push_w), push_w_consumed);
	static const size_t nop_push_w_consumed[] = { 0, 2, 2, 2, 2, 6 };
	ok &= check_truncations(handle, "nop_push_w", code_nop_push_w,
				sizeof(code_nop_push_w), nop_push_w_consumed);

	static const char *const mn_push_w[] = { "push.w" };
	static const char *const ops_push_w[] = { "{r4, r5, r6, r7, r8, lr}" };
	ok &= check_full_decode(handle, code_push_w, sizeof(code_push_w),
				mn_push_w, ops_push_w, 1);
	static const char *const mn_mixed[] = { "nop", "push.w" };
	static const char *const ops_mixed[] = { "",
						 "{r4, r5, r6, r7, r8, lr}" };
	ok &= check_full_decode(handle, code_nop_push_w,
				sizeof(code_nop_push_w), mn_mixed, ops_mixed,
				2);

	cs_close(&handle);
	if (ok) {
		printf("All tests passed.\n");
	}
	return ok ? 0 : -1;
}
