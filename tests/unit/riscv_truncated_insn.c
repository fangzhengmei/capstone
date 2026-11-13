// SPDX-License-Identifier: BSD-3

// Truncated RISC-V instructions at the end of the input buffer. The lowest
// two bits of an encoding select 16-bit (compressed) or 32-bit length, so
// a buffer ending inside a 32-bit instruction must fail without reading
// past it.

#include "truncated_input.h"

// 01 00          c.nop (16-bit compressed)
static const uint8_t code_c_nop[] = { 0x01, 0x00 };
// 13 05 00 00    addi a0, zero, 0 (32-bit)
static const uint8_t code_addi[] = { 0x13, 0x05, 0x00, 0x00 };
// c.nop, then the 32-bit addi above
static const uint8_t code_c_nop_addi[] = { 0x01, 0x00, 0x13, 0x05, 0x00, 0x00 };

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		    &handle) != CS_ERR_OK) {
		printf("cs_open failed\n");
		return -1;
	}
	bool ok = true;

	static const size_t c_nop_consumed[] = { 0, 2 };
	ok &= check_truncations(handle, "c_nop", code_c_nop, sizeof(code_c_nop),
				c_nop_consumed);
	static const size_t addi_consumed[] = { 0, 0, 0, 4 };
	ok &= check_truncations(handle, "addi", code_addi, sizeof(code_addi),
				addi_consumed);
	static const size_t c_nop_addi_consumed[] = { 0, 2, 2, 2, 2, 6 };
	ok &= check_truncations(handle, "c_nop_addi", code_c_nop_addi,
				sizeof(code_c_nop_addi), c_nop_addi_consumed);

	static const char *const mn_c_nop[] = { "nop" };
	static const char *const ops_c_nop[] = { "" };
	ok &= check_full_decode(handle, code_c_nop, sizeof(code_c_nop),
				mn_c_nop, ops_c_nop, 1);
	static const char *const mn_addi[] = { "li" };
	static const char *const ops_addi[] = { "a0, 0" };
	ok &= check_full_decode(handle, code_addi, sizeof(code_addi), mn_addi,
				ops_addi, 1);
	static const char *const mn_mixed[] = { "nop", "li" };
	static const char *const ops_mixed[] = { "", "a0, 0" };
	ok &= check_full_decode(handle, code_c_nop_addi,
				sizeof(code_c_nop_addi), mn_mixed, ops_mixed,
				2);

	cs_close(&handle);
	if (ok) {
		printf("All tests passed.\n");
	}
	return ok ? 0 : -1;
}
