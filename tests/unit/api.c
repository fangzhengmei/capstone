// Copyright © 2026 Rot127 <rot127@posteo.com>
// SPDX-License-Identifier: BSD-3

#include "../../include/capstone/capstone.h"
#include "unit_test.h"
#include <stdio.h>
#include <string.h>

#ifdef CAPSTONE_HAS_X86
#include "../../include/capstone/x86.h"
#endif

static bool test_cs_mem_setup_fail()
{
	printf("Test test_cs_mem_setup_fail\n");
	cs_opt_mem mem = { .malloc = malloc,
			   .calloc = calloc,
			   .realloc = realloc,
			   .free = free,
			   .vsnprintf = NULL };
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.vsnprintf = vsnprintf;
	mem.malloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.malloc = malloc;
	mem.calloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.calloc = calloc;
	mem.realloc = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.realloc = realloc;
	mem.free = NULL;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_MEMSETUP);
	mem.free = free;
	CHECK_INT_EQUAL_RET_FALSE((size_t)cs_option(0, CS_OPT_MEM,
						    (size_t)&mem),
				  CS_ERR_OK);

	return true;
}

#ifdef CAPSTONE_HAS_X86
// push rbp; mov rbp, rsp; <invalid>; pop rbp; ret
static const uint8_t x86_64_code[] = "\x55\x48\x89\xe5\xff\xff\x5d\xc3";
#define X86_64_BASE 0x1000

static bool open_x86_64(csh *handle)
{
	if (cs_open(CS_ARCH_X86, CS_MODE_64, handle) != CS_ERR_OK) {
		printf("Failed to open x86-64 handle\n");
		return false;
	}
	return true;
}

// A failed cs_disasm_try() call must not change the cursor, the address
// or the details of the last confirmed instruction.
static bool test_cs_disasm_try_failed_attempt()
{
	printf("Test test_cs_disasm_try_failed_attempt\n");
	csh handle;
	cs_insn *insn;
	const uint8_t *code;
	size_t size;
	uint64_t address;
	bool result = false;

	if (!open_x86_64(&handle))
		return false;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		printf("Failed to enable details\n");
		goto cleanup_handle;
	}

	insn = cs_malloc(handle);
	if (!insn) {
		printf("cs_malloc failed\n");
		goto cleanup_handle;
	}

	code = x86_64_code;
	size = sizeof(x86_64_code) - 1;
	address = X86_64_BASE;

	// confirm one instruction: push rbp
	if (!cs_disasm_try(handle, &code, &size, &address, insn)) {
		printf("cs_disasm_try failed on valid instruction\n");
		goto cleanup;
	}
	CHECK_STR_EQUAL_RET_FALSE(insn->mnemonic, "push");
	CHECK_STR_EQUAL_RET_FALSE(insn->op_str, "rbp");
	if (insn->address != X86_64_BASE || insn->size != 1 ||
	    address != X86_64_BASE + 1 || size != sizeof(x86_64_code) - 2 ||
	    code != x86_64_code + 1) {
		printf("cursor not advanced by 1 byte\n");
		goto cleanup;
	}
	if (!insn->detail || insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].type != X86_OP_REG ||
	    insn->detail->x86.operands[0].reg != X86_REG_RBP) {
		printf("unexpected details for push rbp\n");
		goto cleanup;
	}

	// skip the valid "mov rbp, rsp" to reach the invalid bytes
	if (!cs_disasm_try(handle, &code, &size, &address, insn)) {
		printf("cs_disasm_try failed on mov\n");
		goto cleanup;
	}
	// confirm the first instruction again, so its details are the
	// last confirmed state
	{
		const uint8_t *first_code = x86_64_code;
		size_t first_size = 1;
		uint64_t first_address = X86_64_BASE;
		if (!cs_disasm_try(handle, &first_code, &first_size,
				   &first_address, insn)) {
			printf("cs_disasm_try failed on first insn\n");
			goto cleanup;
		}
	}

	// attempt to decode the invalid 0xff 0xff: must fail and
	// leave cursor, address and the confirmed instruction untouched
	{
		const uint8_t *bad_code = x86_64_code + 4;
		size_t bad_size = 2;
		uint64_t bad_address = X86_64_BASE + 4;
		if (cs_disasm_try(handle, &bad_code, &bad_size, &bad_address,
				  insn)) {
			printf("cs_disasm_try decoded invalid bytes\n");
			goto cleanup;
		}
		if (bad_code != x86_64_code + 4 || bad_size != 2 ||
		    bad_address != X86_64_BASE + 4) {
			printf("failed attempt changed the cursor\n");
			goto cleanup;
		}
	}
	CHECK_STR_EQUAL_RET_FALSE(insn->mnemonic, "push");
	CHECK_STR_EQUAL_RET_FALSE(insn->op_str, "rbp");
	if (insn->address != X86_64_BASE || insn->size != 1) {
		printf("failed attempt changed the confirmed instruction\n");
		goto cleanup;
	}
	if (!insn->detail || insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].reg != X86_REG_RBP) {
		printf("failed attempt changed the confirmed details\n");
		goto cleanup;
	}

	// a truncated instruction must fail the same way
	{
		const uint8_t *trunc_code = (const uint8_t *)"\x0f";
		size_t trunc_size = 1;
		uint64_t trunc_address = X86_64_BASE;
		if (cs_disasm_try(handle, &trunc_code, &trunc_size,
				  &trunc_address, insn)) {
			printf("cs_disasm_try decoded truncated insn\n");
			goto cleanup;
		}
		if (trunc_size != 1 || trunc_address != X86_64_BASE) {
			printf("truncated attempt changed the cursor\n");
			goto cleanup;
		}
	}
	CHECK_STR_EQUAL_RET_FALSE(insn->mnemonic, "push");

	result = true;
cleanup:
	cs_free(insn, 1);
cleanup_handle:
	cs_close(&handle);
	return result;
}

// Details must be accurate even if CS_OPT_DETAIL is turned on after
// cs_malloc() allocated the instruction cache without a detail buffer.
static bool test_cs_disasm_try_detail_toggle()
{
	printf("Test test_cs_disasm_try_detail_toggle\n");
	csh handle;
	cs_insn *insn;
	const uint8_t *code = x86_64_code;
	size_t size = sizeof(x86_64_code) - 1;
	uint64_t address = X86_64_BASE;
	bool result = false;

	if (!open_x86_64(&handle))
		return false;

	// allocate the cache while details are still disabled
	insn = cs_malloc(handle);
	if (!insn) {
		printf("cs_malloc failed\n");
		goto cleanup_handle;
	}
	CHECK_NULL_RET_FALSE(insn->detail);

	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		printf("Failed to enable details\n");
		goto cleanup;
	}

	if (!cs_disasm_try(handle, &code, &size, &address, insn)) {
		printf("cs_disasm_try failed after detail toggle\n");
		goto cleanup;
	}
	CHECK_STR_EQUAL_RET_FALSE(insn->mnemonic, "push");
	CHECK_STR_EQUAL_RET_FALSE(insn->op_str, "rbp");
	if (!insn->detail) {
		printf("detail buffer missing after detail toggle\n");
		goto cleanup;
	}
	if (insn->detail->x86.op_count != 1 ||
	    insn->detail->x86.operands[0].type != X86_OP_REG ||
	    insn->detail->x86.operands[0].reg != X86_REG_RBP) {
		printf("inaccurate operands after detail toggle\n");
		goto cleanup;
	}

	result = true;
cleanup:
	cs_free(insn, 1);
cleanup_handle:
	cs_close(&handle);
	return result;
}

// With CS_OPT_SKIPDATA enabled, broken bytes become "data" instructions;
// with the policy disabled again, the same bytes must fail without
// touching the cursor. cs_disasm_iter() keeps its advance convention.
static bool test_cs_disasm_try_skipdata_toggle()
{
	printf("Test test_cs_disasm_try_skipdata_toggle\n");
	// push rbp; <invalid>; <invalid>; pop rbp
	static const uint8_t code_buf[] = "\x55\xff\xff\x5d";
	csh handle;
	cs_insn *insn;
	const uint8_t *code;
	size_t size;
	uint64_t address;
	bool result = false;

	if (!open_x86_64(&handle))
		return false;
	if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON) != CS_ERR_OK) {
		printf("Failed to enable skipdata\n");
		goto cleanup_handle;
	}

	insn = cs_malloc(handle);
	if (!insn) {
		printf("cs_malloc failed\n");
		goto cleanup_handle;
	}

	code = code_buf;
	size = sizeof(code_buf) - 1;
	address = X86_64_BASE;

	if (!cs_disasm_try(handle, &code, &size, &address, insn) ||
	    insn->id != X86_INS_PUSH) {
		printf("expected push\n");
		goto cleanup;
	}
	// each invalid byte becomes a 1 byte "data" instruction
	for (int i = 0; i < 2; i++) {
		if (!cs_disasm_try(handle, &code, &size, &address, insn)) {
			printf("skipdata attempt failed\n");
			goto cleanup;
		}
		if (insn->id != 0 || insn->size != 1 ||
		    insn->address != X86_64_BASE + 1 + i) {
			printf("unexpected data instruction\n");
			goto cleanup;
		}
	}
	if (!cs_disasm_try(handle, &code, &size, &address, insn) ||
	    insn->id != X86_INS_POP || size != 0) {
		printf("expected pop at the end of the buffer\n");
		goto cleanup;
	}

	// cs_disasm_iter() keeps its convention of advancing over data
	{
		const uint8_t *iter_code = code_buf + 1;
		size_t iter_size = 2;
		uint64_t iter_address = X86_64_BASE + 1;
		if (!cs_disasm_iter(handle, &iter_code, &iter_size,
				    &iter_address, insn)) {
			printf("cs_disasm_iter skipdata failed\n");
			goto cleanup;
		}
		if (iter_size != 1 || iter_address != X86_64_BASE + 2) {
			printf("cs_disasm_iter advance convention changed\n");
			goto cleanup;
		}
	}

	// disable the skip policy: the invalid bytes must fail cleanly now
	if (cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF) != CS_ERR_OK) {
		printf("Failed to disable skipdata\n");
		goto cleanup;
	}
	{
		const uint8_t *bad_code = code_buf + 1;
		size_t bad_size = 2;
		uint64_t bad_address = X86_64_BASE + 1;
		if (cs_disasm_try(handle, &bad_code, &bad_size, &bad_address,
				  insn)) {
			printf("cs_disasm_try decoded skipped data\n");
			goto cleanup;
		}
		if (bad_code != code_buf + 1 || bad_size != 2 ||
		    bad_address != X86_64_BASE + 1) {
			printf("failed attempt changed the cursor\n");
			goto cleanup;
		}
	}

	result = true;
cleanup:
	cs_free(insn, 1);
cleanup_handle:
	cs_close(&handle);
	return result;
}

// Instruction boundaries found by cs_disasm_try() must match the ones
// reported by cs_disasm() on the same buffer.
static bool test_cs_disasm_try_matches_batch()
{
	printf("Test test_cs_disasm_try_matches_batch\n");
	csh handle;
	cs_insn *batch = NULL;
	cs_insn *insn;
	const uint8_t *code;
	size_t size;
	uint64_t address;
	size_t count, i;
	bool result = false;

	if (!open_x86_64(&handle))
		return false;
	if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
		printf("Failed to enable details\n");
		goto cleanup_handle;
	}

	count = cs_disasm(handle, x86_64_code, 4, X86_64_BASE, 0, &batch);
	if (count != 2) {
		printf("cs_disasm returned %zu instructions\n", count);
		goto cleanup_handle;
	}

	insn = cs_malloc(handle);
	if (!insn) {
		printf("cs_malloc failed\n");
		goto cleanup;
	}

	code = x86_64_code;
	size = 4;
	address = X86_64_BASE;
	for (i = 0; i < count; i++) {
		if (!cs_disasm_try(handle, &code, &size, &address, insn)) {
			printf("cs_disasm_try failed on insn %zu\n", i);
			goto cleanup_iter;
		}
		if (insn->id != batch[i].id ||
		    insn->address != batch[i].address ||
		    insn->size != batch[i].size ||
		    strcmp(insn->mnemonic, batch[i].mnemonic) != 0 ||
		    strcmp(insn->op_str, batch[i].op_str) != 0) {
			printf("boundary mismatch on insn %zu\n", i);
			goto cleanup_iter;
		}
	}
	if (size != 0 || address != X86_64_BASE + 4) {
		printf("cs_disasm_try did not consume the buffer\n");
		goto cleanup_iter;
	}

	result = true;
cleanup_iter:
	cs_free(insn, 1);
cleanup:
	cs_free(batch, count);
cleanup_handle:
	cs_close(&handle);
	return result;
}
#endif // CAPSTONE_HAS_X86

int main()
{
	bool result = true;
	result &= test_cs_mem_setup_fail();
#ifdef CAPSTONE_HAS_X86
	result &= test_cs_disasm_try_failed_attempt();
	result &= test_cs_disasm_try_detail_toggle();
	result &= test_cs_disasm_try_skipdata_toggle();
	result &= test_cs_disasm_try_matches_batch();
#endif

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
