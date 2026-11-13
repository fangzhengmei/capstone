// SPDX-License-Identifier: BSD-3

// Truncated x86 instructions at the end of the input buffer. Legacy, REX
// and VEX prefixes and escape opcodes must not let the decoder read past
// the given buffer, and every truncated length must fail to decode.

#include "truncated_input.h"

// f3 0f 1e fa    endbr64 (REP prefix + 0F escape opcode)
static const uint8_t code_endbr64[] = { 0xf3, 0x0f, 0x1e, 0xfa };
// 48 89 d8       mov rax, rbx (REX.W prefix)
static const uint8_t code_mov_rex[] = { 0x48, 0x89, 0xd8 };
// c5 f8 77       vzeroupper (2-byte VEX prefix)
static const uint8_t code_vzeroupper[] = { 0xc5, 0xf8, 0x77 };
// 16 operand-size prefixes: past the 15 byte instruction length limit.
static const uint8_t code_prefix_overflow[] = {
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};
// 14 prefixes + nop: 15 bytes, the longest legal x86 instruction.
static const uint8_t code_max_len_nop[] = {
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x90,
};

int main(void)
{
	csh handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		printf("cs_open failed\n");
		return -1;
	}
	bool ok = true;

	static const size_t endbr64_consumed[] = { 0, 0, 0, 4 };
	ok &= check_truncations(handle, "endbr64", code_endbr64,
				sizeof(code_endbr64), endbr64_consumed);
	static const size_t mov_rex_consumed[] = { 0, 0, 3 };
	ok &= check_truncations(handle, "mov_rex", code_mov_rex,
				sizeof(code_mov_rex), mov_rex_consumed);
	static const size_t vzeroupper_consumed[] = { 0, 0, 3 };
	ok &= check_truncations(handle, "vzeroupper", code_vzeroupper,
				sizeof(code_vzeroupper), vzeroupper_consumed);
	static const size_t prefix_overflow_consumed[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	};
	ok &= check_truncations(handle, "prefix_overflow", code_prefix_overflow,
				sizeof(code_prefix_overflow),
				prefix_overflow_consumed);
	static const size_t max_len_nop_consumed[] = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15,
	};
	ok &= check_truncations(handle, "max_len_nop", code_max_len_nop,
				sizeof(code_max_len_nop), max_len_nop_consumed);

	static const char *const mn_endbr64[] = { "endbr64" };
	static const char *const ops_endbr64[] = { "" };
	ok &= check_full_decode(handle, code_endbr64, sizeof(code_endbr64),
				mn_endbr64, ops_endbr64, 1);
	static const char *const mn_mov[] = { "mov" };
	static const char *const ops_mov[] = { "rax, rbx" };
	ok &= check_full_decode(handle, code_mov_rex, sizeof(code_mov_rex),
				mn_mov, ops_mov, 1);
	static const char *const mn_vzeroupper[] = { "vzeroupper" };
	static const char *const ops_vzeroupper[] = { "" };
	ok &= check_full_decode(handle, code_vzeroupper,
				sizeof(code_vzeroupper), mn_vzeroupper,
				ops_vzeroupper, 1);
	static const char *const mn_nop[] = { "nop" };
	static const char *const ops_nop[] = { "" };
	ok &= check_full_decode(handle, code_max_len_nop,
				sizeof(code_max_len_nop), mn_nop, ops_nop, 1);

	cs_close(&handle);
	if (ok) {
		printf("All tests passed.\n");
	}
	return ok ? 0 : -1;
}
