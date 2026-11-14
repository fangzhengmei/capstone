// SPDX-License-Identifier: BSD-3
// SPDX-FileCopyrightText: 2026 Rot127 <rot127@posteo.com>

// Regression tests for allocation failures in the handle, decoder and
// printer stages. Every allocation site reachable from cs_open(),
// cs_disasm(), cs_disasm_iter() and cs_malloc() is failed one at a time
// through the user supplied allocator (CS_OPT_MEM). Each run must report
// CS_ERR_MEM, return no instructions and leave no allocation behind.

#include "../../include/capstone/capstone.h"
#include "unit_test.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_TRACKED_ALLOCS 1024
#define MAX_BATCH_INSNS 40

/// Allocation bookkeeping of the injectable allocator.
static struct {
	void *ptr;
	bool live;
} tracked[MAX_TRACKED_ALLOCS];

static long inject_at = -1; ///< Fail the allocation call with this index.
static long alloc_calls; ///< Number of allocator calls since the last reset.
static long outstanding; ///< Live allocations.
static bool injection_fired; ///< The injected failure was reached.
static bool invalid_free; ///< A foreign or already released pointer was freed.

static void reset_allocator_state(void)
{
	memset(tracked, 0, sizeof(tracked));
	inject_at = -1;
	alloc_calls = 0;
	outstanding = 0;
	injection_fired = false;
	invalid_free = false;
}

static bool should_fail(void)
{
	bool fail = inject_at >= 0 && alloc_calls == inject_at;
	alloc_calls++;
	if (fail)
		injection_fired = true;
	return fail;
}

static void track(void *ptr)
{
	if (!ptr)
		return;
	for (size_t i = 0; i < MAX_TRACKED_ALLOCS; i++) {
		if (!tracked[i].live) {
			tracked[i].ptr = ptr;
			tracked[i].live = true;
			outstanding++;
			return;
		}
	}
	// Bookkeeping exhaustion is a test bug, not a library failure.
	fprintf(stderr, "allocator test: tracking table exhausted\n");
	abort();
}

static bool untrack(void *ptr)
{
	for (size_t i = 0; i < MAX_TRACKED_ALLOCS; i++) {
		if (tracked[i].live && tracked[i].ptr == ptr) {
			tracked[i].live = false;
			tracked[i].ptr = NULL;
			outstanding--;
			return true;
		}
	}
	return false;
}

static void *CAPSTONE_API test_malloc(size_t size)
{
	if (should_fail())
		return NULL;
	void *ptr = malloc(size);
	track(ptr);
	return ptr;
}

static void *CAPSTONE_API test_calloc(size_t num, size_t size)
{
	if (should_fail())
		return NULL;
	void *ptr = calloc(num, size);
	track(ptr);
	return ptr;
}

static void *CAPSTONE_API test_realloc(void *ptr, size_t size)
{
	if (should_fail())
		// Like realloc(), leave the old block untouched.
		return NULL;
	if (ptr)
		untrack(ptr);
	void *new_ptr = realloc(ptr, size);
	track(new_ptr);
	return new_ptr;
}

static void CAPSTONE_API test_free(void *ptr)
{
	if (!ptr)
		return;
	if (!untrack(ptr))
		// Freeing an unknown or already released pointer.
		invalid_free = true;
	free(ptr);
}

static bool install_test_allocator(void)
{
	cs_opt_mem mem = { test_malloc, test_calloc, test_realloc,
			   test_free, vsnprintf };
	return cs_option(0, CS_OPT_MEM, (size_t)&mem) == CS_ERR_OK;
}

static bool install_default_allocator(void)
{
	cs_opt_mem mem = { malloc, calloc, realloc, free, vsnprintf };
	return cs_option(0, CS_OPT_MEM, (size_t)&mem) == CS_ERR_OK;
}

/// Outcome of a single scenario run with an injected failure point.
typedef enum {
	SCENARIO_OK, ///< Everything succeeded, no allocation failed.
	SCENARIO_INJECTED, ///< The injected allocation failed and rolled back.
	SCENARIO_FAIL, ///< The contract was violated.
} scenario_result;

/// Runs @run once per allocation index until a run completes without the
/// injected failure. Every run must leave the allocator balanced.
static bool sweep_allocation_points(scenario_result (*run)(void *),
				    void *ctx, const char *name)
{
	if (!install_test_allocator()) {
		fprintf(stderr, "  %s: failed to install test allocator\n",
			name);
		return false;
	}

	// The first run counts the allocation sites of the scenario.
	reset_allocator_state();
	scenario_result first = run(ctx);
	long total_allocations = alloc_calls;
	if (first != SCENARIO_OK || outstanding != 0 || invalid_free) {
		fprintf(stderr, "  %s: reference run failed (%d, %ld live)\n",
			name, (int)first, outstanding);
		install_default_allocator();
		return false;
	}

	for (long fail_at = 0; fail_at < total_allocations; fail_at++) {
		reset_allocator_state();
		inject_at = fail_at;
		if (run(ctx) == SCENARIO_FAIL) {
			fprintf(stderr, "  %s: failure at allocation %ld\n",
				name, fail_at);
			install_default_allocator();
			return false;
		}
		if (outstanding != 0 || invalid_free) {
			fprintf(stderr,
				"  %s: failure at allocation %ld leaked %ld, invalid free %d\n",
				name, fail_at, outstanding, (int)invalid_free);
			install_default_allocator();
			return false;
		}
		if (!injection_fired) {
			// This index is beyond the allocation sites of this
			// scenario; the remaining sweep would repeat the reference
			// run. The reference run already checked its output.
			break;
		}
	}

	return install_default_allocator();
}

// ---------------------------------------------------------------------------
// cs_open() / cs_close()
// ---------------------------------------------------------------------------

typedef struct {
	cs_arch arch;
	cs_mode mode;
	size_t expected_insns;
	const uint8_t *code;
	size_t code_size;
} open_ctx;

static scenario_result open_scenario(void *ctxp)
{
	const open_ctx *ctx = ctxp;
	csh handle = 0;
	cs_err err = cs_open(ctx->arch, ctx->mode, &handle);

	if (err != CS_ERR_OK || handle == 0) {
		// A partially initialized handle must not be handed out.
		if (err == CS_ERR_MEM && handle == 0)
			return SCENARIO_INJECTED;
		return SCENARIO_FAIL;
	}

	// The handle must be fully usable, so that a partial initialization
	// cannot go unnoticed.
	cs_insn *insns = NULL;
	size_t count = cs_disasm(handle, ctx->code, ctx->code_size, 0x1000, 0,
				 &insns);
	cs_err errnum = cs_errno(handle);
	cs_free(insns, count);
	if (cs_close(&handle) != CS_ERR_OK || handle != 0)
		return SCENARIO_FAIL;

	if (injection_fired) {
		// This run failed while disassembling, not while opening.
		return count == 0 && errnum == CS_ERR_MEM ? SCENARIO_INJECTED :
							    SCENARIO_FAIL;
	}

	if (count != ctx->expected_insns || errnum != CS_ERR_OK)
		return SCENARIO_FAIL;

	return SCENARIO_OK;
}

static bool test_open_failure_points(cs_arch arch, cs_mode mode,
				     const uint8_t *code, size_t code_size,
				     size_t expected_insns, const char *name)
{
	open_ctx ctx = { arch, mode, expected_insns, code, code_size };
	return sweep_allocation_points(open_scenario, &ctx, name);
}

// ---------------------------------------------------------------------------
// cs_disasm() batches
// ---------------------------------------------------------------------------

typedef struct {
	cs_arch arch;
	cs_mode mode;
	const uint8_t *code;
	size_t code_size;
	size_t expected_insns;
	size_t first_size;
	const char *first_mnemonic;
	const char *first_op_str;
} batch_ctx;

static scenario_result batch_scenario(void *ctxp)
{
	const batch_ctx *ctx = ctxp;
	csh handle = 0;

	if (cs_open(ctx->arch, ctx->mode, &handle) != CS_ERR_OK)
		return injection_fired ? SCENARIO_INJECTED : SCENARIO_FAIL;

	(void)cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insns = NULL;
	size_t count = cs_disasm(handle, ctx->code, ctx->code_size, 0x1000, 0,
				 &insns);
	cs_err errnum = cs_errno(handle);

	if (injection_fired) {
		// A failed batch must report CS_ERR_MEM and hand back nothing.
		if (count != 0 || insns != NULL || errnum != CS_ERR_MEM) {
			cs_free(insns, count);
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
	} else {
		if (count != ctx->expected_insns || errnum != CS_ERR_OK) {
			fprintf(stderr, "    got %zu insns, err %d\n", count,
				(int)errnum);
			cs_free(insns, count);
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
		if (strcmp(insns[0].mnemonic, ctx->first_mnemonic) != 0 ||
		    strcmp(insns[0].op_str, ctx->first_op_str) != 0 ||
		    insns[0].size != ctx->first_size) {
			fprintf(stderr, "    got '%s %s', want '%s %s'\n",
				insns[0].mnemonic, insns[0].op_str,
				ctx->first_mnemonic, ctx->first_op_str);
			cs_free(insns, count);
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
	}

	cs_free(insns, count);
	if (cs_close(&handle) != CS_ERR_OK)
		return SCENARIO_FAIL;

	return injection_fired ? SCENARIO_INJECTED : SCENARIO_OK;
}

// ---------------------------------------------------------------------------
// cs_malloc() / cs_disasm_iter()
// ---------------------------------------------------------------------------

typedef struct {
	const uint8_t *code;
	size_t code_size;
	const char *mnemonic;
	const char *op_str;
} iter_ctx;

static scenario_result iter_scenario(void *ctxp){
	const iter_ctx *ctx = ctxp;
	csh handle = 0;

	if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK)
		return injection_fired ? SCENARIO_INJECTED : SCENARIO_FAIL;

	(void)cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn = cs_malloc(handle);
	if (!insn) {
		// cs_malloc() hands out nothing on failure and reports it.
		if (!injection_fired || cs_errno(handle) != CS_ERR_MEM) {
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
		if (cs_close(&handle) != CS_ERR_OK)
			return SCENARIO_FAIL;
		return SCENARIO_INJECTED;
	}

	const uint8_t *code = ctx->code;
	size_t size = ctx->code_size;
	uint64_t address = 0x1000;
	bool iterated = cs_disasm_iter(handle, &code, &size, &address, insn);
	cs_err errnum = cs_errno(handle);

	if (injection_fired) {
		// A failed iteration consumes no input and reports CS_ERR_MEM.
		if (iterated || errnum != CS_ERR_MEM ||
		    size != ctx->code_size || code != ctx->code ||
		    address != 0x1000) {
			cs_free(insn, 1);
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
	} else if (!iterated || errnum != CS_ERR_OK ||
		   strcmp(insn->mnemonic, ctx->mnemonic) != 0 ||
		   strcmp(insn->op_str, ctx->op_str) != 0 ||
		   insn->size != ctx->code_size) {
		cs_free(insn, 1);
		cs_close(&handle);
		return SCENARIO_FAIL;
	}

	cs_free(insn, 1);
	if (cs_close(&handle) != CS_ERR_OK)
		return SCENARIO_FAIL;

	return injection_fired ? SCENARIO_INJECTED : SCENARIO_OK;
}

// ---------------------------------------------------------------------------
// SKIPDATA must not absorb an allocator failure
// ---------------------------------------------------------------------------

static scenario_result skipdata_scenario(void *ctxp)
{
	static const uint8_t ebpf_mov[] = { 0xb7, 0x00, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00 };
	(void)ctxp;

	csh handle = 0;
	if (cs_open(CS_ARCH_BPF, CS_MODE_BPF_EXTENDED, &handle) != CS_ERR_OK)
		return injection_fired ? SCENARIO_INJECTED : SCENARIO_FAIL;

	cs_opt_skipdata skip = { .mnemonic = ".byte",
				 .callback = NULL,
				 .user_data = NULL };
	(void)cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	(void)cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skip);
	(void)cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insns = NULL;
	size_t count = cs_disasm(handle, ebpf_mov, sizeof(ebpf_mov), 0x1000, 0,
				 &insns);
	cs_err errnum = cs_errno(handle);

	if (injection_fired) {
		// The decoder allocates per instruction. With skipdata enabled a
		// NULL return used to be mistaken for malformed code and turned
		// into a ".byte" instruction.
		if (count != 0 || insns != NULL || errnum != CS_ERR_MEM) {
			cs_free(insns, count);
			cs_close(&handle);
			return SCENARIO_FAIL;
		}
	} else if (count != 1 || errnum != CS_ERR_OK ||
		   strcmp(insns[0].mnemonic, "mov64") != 0 ||
		   strcmp(insns[0].op_str, "r0, 0x0") != 0) {
		cs_free(insns, count);
		cs_close(&handle);
		return SCENARIO_FAIL;
	}

	cs_free(insns, count);
	if (cs_close(&handle) != CS_ERR_OK)
		return SCENARIO_FAIL;

	return injection_fired ? SCENARIO_INJECTED : SCENARIO_OK;
}

// ---------------------------------------------------------------------------
// Malformed and truncated input
// ---------------------------------------------------------------------------

/// One instruction per arch whose printer takes the generated alias path.
typedef struct {
	cs_arch arch;
	cs_mode mode;
	const char *name;
	uint8_t code[4];
	const char *mnemonic;
	const char *op_str;
} alias_case;

static const alias_case alias_cases[] = {
	{ CS_ARCH_ARM, CS_MODE_ARM, "arm alias", { 0x00, 0x12, 0xa0, 0xe1 },
	  "lsl", "r1, r0, #4" },
	{ CS_ARCH_RISCV, CS_MODE_RISCV64, "riscv alias",
	  { 0x13, 0x00, 0x00, 0x00 }, "nop", "" },
	{ CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN, "ppc alias",
	  { 0x7c, 0x08, 0x02, 0xa6 }, "mflr", "r0" },
	{ CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, "sparc alias",
	  { 0x9d, 0xe3, 0xbf, 0xa0 }, "save", "%sp, -0x60, %sp" },
	{ CS_ARCH_LOONGARCH, CS_MODE_LOONGARCH64, "loongarch alias",
	  { 0x00, 0x00, 0x00, 0x03 }, "lu52i.d", "$zero, $zero, 0" },
};

static scenario_result malformed_scenario(void *ctxp)
{
	static const uint8_t truncated[] = { 0xe1, 0x03, 0x00 };
	static const uint8_t malformed[] = { 0xff, 0xff, 0xff, 0xff };
	const uint8_t *inputs[] = { truncated, malformed };
	size_t sizes[] = { sizeof(truncated), sizeof(malformed) };
	(void)ctxp;

	csh handle = 0;
	if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK)
		return injection_fired ? SCENARIO_INJECTED : SCENARIO_FAIL;

	for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
		for (int run = 0; run < 2; run++) {
			cs_insn *insns = NULL;
			size_t count = cs_disasm(handle, inputs[i], sizes[i],
						 0x1000, 0, &insns);
			// The same input must produce the same result each time.
			if (count != 0 || insns != NULL ||
			    cs_errno(handle) != CS_ERR_OK) {
				cs_free(insns, count);
				cs_close(&handle);
				return injection_fired ? SCENARIO_INJECTED :
							 SCENARIO_FAIL;
			}
		}
	}

	if (cs_close(&handle) != CS_ERR_OK)
		return SCENARIO_FAIL;

	return injection_fired ? SCENARIO_INJECTED : SCENARIO_OK;
}

/// Scenarios are skipped for architectures which were not compiled in, or
/// were not registered with CS_OPT_MEM style registration builds.
static bool arch_available(cs_arch arch)
{
	if (cs_support(arch))
		return true;
	printf("  skipping unavailable arch %d\n", (int)arch);
	return false;
}

int main()
{
	bool result = true;
	static const uint8_t mov_x1_x0[] = { 0xe1, 0x03, 0x00, 0xaa };
	static const uint8_t movaz_tile[] = { 0x00, 0x02, 0xc3, 0xc0 };
	static const uint8_t x64_mov[] = { 0x48, 0x89, 0xe5 };
	uint8_t batch[MAX_BATCH_INSNS * 4];

	for (size_t i = 0; i < MAX_BATCH_INSNS; i++)
		memcpy(batch + i * 4, mov_x1_x0, 4);

	printf("Test test_open_failure_points\n");
	if (arch_available(CS_ARCH_X86))
		result &= test_open_failure_points(CS_ARCH_X86, CS_MODE_64,
						   x64_mov, sizeof(x64_mov), 1,
						   "x86 open");
	if (arch_available(CS_ARCH_AARCH64))
		result &= test_open_failure_points(
			CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, movaz_tile,
			sizeof(movaz_tile), 1, "aarch64 open");
	if (arch_available(CS_ARCH_BPF))
		result &= test_open_failure_points(CS_ARCH_BPF,
						   CS_MODE_BPF_EXTENDED, x64_mov,
						   0, 0, "bpf open");

	printf("Test test_disasm_failure_points\n");
	if (arch_available(CS_ARCH_AARCH64)) {
		batch_ctx batch_a64 = { CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN,
					batch, sizeof(batch),
					MAX_BATCH_INSNS, 4, "mov",
					"x1, x0" };
		result &= sweep_allocation_points(batch_scenario, &batch_a64,
						  "aarch64 batch");

		// printMatrixTileVector() splits the ZA register name in a heap
		// buffer, so this covers the allocation in the AArch64 printer
		// outside of the generated alias code.
		batch_ctx batch_za = { CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN,
				       movaz_tile, sizeof(movaz_tile), 1,
				       sizeof(movaz_tile), "movaz",
				       "z0.q, za0h.q[w12, 0]" };
		result &= sweep_allocation_points(batch_scenario, &batch_za,
						  "aarch64 za batch");
	}

	if (arch_available(CS_ARCH_X86)) {
		batch_ctx batch_x86 = { CS_ARCH_X86, CS_MODE_64, x64_mov,
					sizeof(x64_mov), 1, 3, "mov",
					"rbp, rsp" };
		result &= sweep_allocation_points(batch_scenario, &batch_x86,
						  "x86 batch");
	}

	// The remaining architectures allocate the mnemonic substring in their
	// generated alias printer as well.
	for (size_t i = 0; i < sizeof(alias_cases) / sizeof(alias_cases[0]);
	     i++) {
		if (!arch_available(alias_cases[i].arch))
			continue;
		batch_ctx alias_batch = { alias_cases[i].arch,
					  alias_cases[i].mode,
					  alias_cases[i].code,
					  sizeof(alias_cases[i].code), 1,
					  sizeof(alias_cases[i].code),
					  alias_cases[i].mnemonic,
					  alias_cases[i].op_str };
		result &= sweep_allocation_points(batch_scenario, &alias_batch,
						  alias_cases[i].name);
	}

	printf("Test test_iter_failure_points\n");
	if (arch_available(CS_ARCH_AARCH64)) {
		iter_ctx iter_a64 = { mov_x1_x0, sizeof(mov_x1_x0), "mov",
				      "x1, x0" };
		result &= sweep_allocation_points(iter_scenario, &iter_a64,
						  "aarch64 iter");
	}

	printf("Test test_decoder_allocation_not_skipdata\n");
	if (arch_available(CS_ARCH_BPF))
		result &= sweep_allocation_points(skipdata_scenario, NULL,
						  "bpf skipdata");

	printf("Test test_malformed_input\n");
	if (arch_available(CS_ARCH_AARCH64))
		result &= sweep_allocation_points(malformed_scenario, NULL,
						  "malformed input");

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}
