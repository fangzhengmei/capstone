// SPDX-License-Identifier: BSD-3

// Shared helpers for the truncated-input decoding tests.
//
// Every truncation length is decoded from an exact-sized heap allocation,
// so ASan and valgrind report any read past the end of the given buffer.
// Each length is decoded with the batch API (cs_disasm) and the iterative
// API (cs_disasm_iter). Both must agree on the number of leading bytes
// they can disassemble, and repeated runs must produce the same result.

#ifndef TRUNCATED_INPUT_H
#define TRUNCATED_INPUT_H

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <capstone/capstone.h>

#define TRUNC_BASE_ADDR 0x1000

// Decodes `len` bytes of `code` from an exact-sized buffer and sets
// `consumed` to the number of leading bytes that disassemble successfully.
// Returns false if batch and iterative decoding disagree, if a repeated run
// differs, or if an instruction covers bytes past the end of the buffer.
static bool truncated_decode(csh handle, const uint8_t *code, size_t len,
			     size_t *consumed)
{
	uint8_t *buf = malloc(len);
	memcpy(buf, code, len);
	bool ok = true;
	*consumed = SIZE_MAX;

	for (int run = 0; run < 2 && ok; run++) {
		cs_insn *insn = NULL;
		size_t count =
			cs_disasm(handle, buf, len, TRUNC_BASE_ADDR, 0, &insn);
		size_t batch = 0;
		for (size_t i = 0; i < count; i++) {
			if (insn[i].address < TRUNC_BASE_ADDR ||
			    insn[i].address - TRUNC_BASE_ADDR + insn[i].size >
				    len) {
				printf("insn %zu spans bytes past the input\n",
				       i);
				ok = false;
			}
			batch += insn[i].size;
		}
		if (insn) {
			cs_free(insn, count);
		}

		cs_insn *it = cs_malloc(handle);
		const uint8_t *p = buf;
		size_t rem = len;
		uint64_t addr = TRUNC_BASE_ADDR;
		while (cs_disasm_iter(handle, &p, &rem, &addr, it)) {
		}
		size_t iter = (size_t)(p - buf);
		cs_free(it, 1);

		if (iter != batch) {
			printf("len=%zu: batch consumed %zu, iter consumed "
			       "%zu\n",
			       len, batch, iter);
			ok = false;
		}
		if (*consumed == SIZE_MAX) {
			*consumed = batch;
		} else if (*consumed != batch) {
			printf("len=%zu: unstable result %zu != %zu\n", len,
			       batch, *consumed);
			ok = false;
		}
	}

	free(buf);
	return ok;
}

// Checks that decoding the complete buffer yields exactly the expected
// instruction texts.
static bool check_full_decode(csh handle, const uint8_t *code, size_t len,
			      const char *const *mnemonics,
			      const char *const *op_strs, size_t n_insns)
{
	uint8_t *buf = malloc(len);
	memcpy(buf, code, len);
	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, buf, len, TRUNC_BASE_ADDR, 0, &insn);
	bool ok = true;

	if (count != n_insns) {
		printf("expected %zu insns, got %zu\n", n_insns, count);
		ok = false;
	}
	for (size_t i = 0; i < count && i < n_insns; i++) {
		if (strcmp(insn[i].mnemonic, mnemonics[i]) != 0 ||
		    strcmp(insn[i].op_str, op_strs[i]) != 0) {
			printf("insn %zu: expected '%s %s', got '%s %s'\n", i,
			       mnemonics[i], op_strs[i], insn[i].mnemonic,
			       insn[i].op_str);
			ok = false;
		}
	}
	if (insn) {
		cs_free(insn, count);
	}
	free(buf);
	return ok;
}

// Runs every truncation length 1..len of `code` and checks the consumed
// prefix against `expected_consumed` (indexed by length - 1).
static bool check_truncations(csh handle, const char *name, const uint8_t *code,
			      size_t len, const size_t *expected_consumed)
{
	bool ok = true;
	for (size_t l = 1; l <= len; l++) {
		size_t consumed = 0;
		if (!truncated_decode(handle, code, l, &consumed)) {
			printf("%s: decode check failed at len=%zu\n", name, l);
			ok = false;
			continue;
		}
		if (consumed != expected_consumed[l - 1]) {
			printf("%s: len=%zu consumed %zu, expected %zu\n", name,
			       l, consumed, expected_consumed[l - 1]);
			ok = false;
		}
	}
	return ok;
}

#endif // TRUNCATED_INPUT_H
