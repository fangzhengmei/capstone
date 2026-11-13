// SPDX-License-Identifier: BSD-3

// A buffer ending with a truncated or malformed instruction must decode up
// to the last complete instruction and no further. The decoder must not
// read past the given buffer: all buffers are exact-sized heap allocations
// so ASan and valgrind catch out-of-bounds reads. Batch (cs_disasm) and
// iterative (cs_disasm_iter) decoding must agree on the failure position,
// and the failure must be stable across repeated runs.

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#define BASE_ADDR 0x1000

static void check(bool cond, const char *msg)
{
	if (!cond) {
		fprintf(stderr, "FAIL: %s\n", msg);
		abort();
	}
}

static size_t batch_consumed(csh handle, const uint8_t *code, size_t len)
{
	uint8_t *buf = malloc(len);
	memcpy(buf, code, len);
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, buf, len, BASE_ADDR, 0, &insn);
	size_t consumed = 0;
	for (size_t i = 0; i < count; i++) {
		check(insn[i].address >= BASE_ADDR &&
			      insn[i].address - BASE_ADDR + insn[i].size <= len,
		      "instruction spans bytes past the input buffer");
		consumed += insn[i].size;
	}
	if (insn) {
		cs_free(insn, count);
	}
	free(buf);
	return consumed;
}

static size_t iter_consumed(csh handle, const uint8_t *code, size_t len)
{
	uint8_t *buf = malloc(len);
	memcpy(buf, code, len);
	cs_insn *insn = cs_malloc(handle);
	const uint8_t *p = buf;
	size_t rem = len;
	uint64_t addr = BASE_ADDR;
	while (cs_disasm_iter(handle, &p, &rem, &addr, insn)) {
	}
	size_t consumed = (size_t)(p - buf);
	cs_free(insn, 1);
	free(buf);
	return consumed;
}

// Both APIs must stop after exactly `expected` bytes, on repeated runs.
static void expect_stop(csh handle, const uint8_t *code, size_t len,
			size_t expected)
{
	for (int run = 0; run < 2; run++) {
		size_t batch = batch_consumed(handle, code, len);
		size_t iter = iter_consumed(handle, code, len);
		check(batch == iter,
		      "batch and iterative decoding disagree on stop offset");
		check(batch == expected, "unexpected stop offset");
	}
}

// Appending `tail` to a complete instruction stream must not change how
// much of it decodes: decoding stops at the end of the stream.
static void expect_stop_with_tail(csh handle, const uint8_t *stream,
				  size_t stream_len, const uint8_t *tail,
				  size_t tail_len)
{
	uint8_t buf[64];
	check(stream_len + tail_len <= sizeof(buf), "test buffer too small");
	memcpy(buf, stream, stream_len);
	memcpy(buf + stream_len, tail, tail_len);
	expect_stop(handle, buf, stream_len + tail_len, stream_len);
}

// The complete stream must decode to exactly the expected texts.
static void expect_full_decode(csh handle, const uint8_t *code, size_t len,
			       const char *const *mnemonics,
			       const char *const *op_strs, size_t n_insns)
{
	uint8_t *buf = malloc(len);
	memcpy(buf, code, len);
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, buf, len, BASE_ADDR, 0, &insn);
	check(count == n_insns, "unexpected instruction count");
	for (size_t i = 0; i < count && i < n_insns; i++) {
		check(strcmp(insn[i].mnemonic, mnemonics[i]) == 0 &&
			      strcmp(insn[i].op_str, op_strs[i]) == 0,
		      "instruction text changed");
	}
	if (insn) {
		cs_free(insn, count);
	}
	free(buf);
}

static void test_x86(void)
{
	if (!cs_support(CS_ARCH_X86)) {
		return;
	}
	csh handle;
	check(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK,
	      "cs_open x86 failed");

	// mov rax, rbx; endbr64
	static const uint8_t stream[] = { 0x48, 0x89, 0xd8, 0xf3,
					  0x0f, 0x1e, 0xfa };
	static const char *const mn[] = { "mov", "endbr64" };
	static const char *const ops[] = { "rax, rbx", "" };
	expect_full_decode(handle, stream, sizeof(stream), mn, ops, 2);
	expect_stop(handle, stream, sizeof(stream), sizeof(stream));

	// Truncated tails: lone prefixes and escape bytes.
	static const uint8_t tail_esc[] = { 0x0f };
	static const uint8_t tail_rex[] = { 0x48 };
	static const uint8_t tail_vex[] = { 0xc5 };
	static const uint8_t tail_prefix[] = { 0x66 };
	static const uint8_t tail_endbr[] = { 0xf3, 0x0f, 0x1e };
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_esc,
			      sizeof(tail_esc));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_rex,
			      sizeof(tail_rex));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_vex,
			      sizeof(tail_vex));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_prefix,
			      sizeof(tail_prefix));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_endbr,
			      sizeof(tail_endbr));

	// Malformed prefix runs: nothing decodable.
	static const uint8_t prefixes_16[] = {
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	};
	static const uint8_t prefixes_15[] = {
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	};
	static const uint8_t prefixes_mixed[] = {
		0xf0, 0x66, 0x67, 0x2e, 0xf0, 0x66, 0x67, 0x2e,
		0xf0, 0x66, 0x67, 0x2e, 0xf0, 0x66, 0x67, 0x2e,
		0xf0, 0x66, 0x67, 0x2e, 0xf0, 0x66, 0x67, 0x2e,
		0xf0, 0x66, 0x67, 0x2e, 0xf0, 0x66, 0x67, 0x2e,
	};
	expect_stop(handle, prefixes_16, sizeof(prefixes_16), 0);
	expect_stop(handle, prefixes_15, sizeof(prefixes_15), 0);
	expect_stop(handle, prefixes_mixed, sizeof(prefixes_mixed), 0);

	cs_close(&handle);
}

static void test_thumb(void)
{
	if (!cs_support(CS_ARCH_ARM)) {
		return;
	}
	csh handle;
	check(cs_open(CS_ARCH_ARM, CS_MODE_THUMB, &handle) == CS_ERR_OK,
	      "cs_open thumb failed");

	// nop; push.w {r4, r5, r6, r7, r8, lr} (mixed 16/32-bit encodings)
	static const uint8_t stream[] = { 0x00, 0xbf, 0x2d, 0xe9, 0xf0, 0x41 };
	static const char *const mn[] = { "nop", "push.w" };
	static const char *const ops[] = { "", "{r4, r5, r6, r7, r8, lr}" };
	expect_full_decode(handle, stream, sizeof(stream), mn, ops, 2);
	expect_stop(handle, stream, sizeof(stream), sizeof(stream));

	// Truncated tails: the 32-bit encoding cut after 1, 2 or 3 bytes.
	static const uint8_t tail_1[] = { 0x2d };
	static const uint8_t tail_2[] = { 0x2d, 0xe9 };
	static const uint8_t tail_3[] = { 0x2d, 0xe9, 0xf0 };
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_1,
			      sizeof(tail_1));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_2,
			      sizeof(tail_2));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_3,
			      sizeof(tail_3));

	// Only the first halfword of a 32-bit encoding: nothing decodable.
	expect_stop(handle, tail_1, sizeof(tail_1), 0);
	expect_stop(handle, tail_2, sizeof(tail_2), 0);
	expect_stop(handle, tail_3, sizeof(tail_3), 0);

	cs_close(&handle);
}

static void test_riscv(void)
{
	if (!cs_support(CS_ARCH_RISCV)) {
		return;
	}
	csh handle;
	check(cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64 | CS_MODE_RISCV_C,
		      &handle) == CS_ERR_OK,
	      "cs_open riscv failed");

	// c.nop; c.ret; addi a0, zero, 0 (mixed 16/32-bit encodings)
	static const uint8_t stream[] = { 0x01, 0x00, 0x82, 0x80,
					  0x13, 0x05, 0x00, 0x00 };
	static const char *const mn[] = { "nop", "ret", "li" };
	static const char *const ops[] = { "", "", "a0, 0" };
	expect_full_decode(handle, stream, sizeof(stream), mn, ops, 3);
	expect_stop(handle, stream, sizeof(stream), sizeof(stream));

	// Truncated tails: the 32-bit encoding cut after 1, 2 or 3 bytes.
	static const uint8_t tail_1[] = { 0x13 };
	static const uint8_t tail_2[] = { 0x13, 0x05 };
	static const uint8_t tail_3[] = { 0x13, 0x05, 0x00 };
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_1,
			      sizeof(tail_1));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_2,
			      sizeof(tail_2));
	expect_stop_with_tail(handle, stream, sizeof(stream), tail_3,
			      sizeof(tail_3));

	// Incomplete encodings alone: nothing decodable.
	expect_stop(handle, tail_1, sizeof(tail_1), 0);
	expect_stop(handle, tail_2, sizeof(tail_2), 0);
	expect_stop(handle, tail_3, sizeof(tail_3), 0);

	cs_close(&handle);
}

int main(void)
{
	test_x86();
	test_thumb();
	test_riscv();
	printf("All tests passed.\n");
	return 0;
}
