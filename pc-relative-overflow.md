# PC 相对目标地址计算的溢出 / 截断 / 回绕不一致分析

调查对象：当恶意或畸形机器码把指令基址（用户提供的 `address` 参数）放到 32 位或 64
位地址上界附近时，各架构对 PC 相对跳转/调用目标地址（`target = address + 位移`）的
计算。对比维度：

1. 是否存在有符号溢出（UB）或实现定义行为；
2. 32 位架构是否把结果截断回地址宽度；
3. 文本输出（`op_str`）与 detail（`cs_detail` 的 `imm`）是否一致；
4. 仅输出偏移模式（`CS_OPT_ONLY_OFFSET_BRANCH`，内部标志
   `PrintBranchImmAsAddress`，见 `cs.c:1199`）下各架构行为是否一致。

测试方法：本地构建（`make`，全架构）后用 `cstool` 及一个链接 `libcapstone` 的小程序
在边界地址上反汇编下列字节样本，同时核对文本与 detail。所有样本均在本仓库当前 HEAD
（823242a）上复现。

## 一、各架构目标地址计算现状

| 架构 | 计算位置 | 回绕宽度 | 文本=detail？ | 支持 offset-only 选项 |
|---|---|---|---|---|
| x86-64 | `arch/X86/X86IntelInstPrinter.c:879`、`X86ATTInstPrinter.c:632` | mod 2^64（无符号回绕） | 是 | 否（总是绝对地址） |
| x86-32 | 同上 | `& 0xffffffff` | 是 | 否 |
| x86-16 | 同上 | **`& 0xffffffff`（未截到 16 位）** | 是 | 否 |
| ARM/Thumb | `arch/ARM/ARMInstPrinter.c:157-183` | `& 0xffffffff` | 是 | 是 |
| AArch64 | `arch/AArch64/AArch64InstPrinter.c:2044-2133`、`AArch64Mapping.c:1506-1561` | mod 2^64 | 是 | 是 |
| PPC32/64 | `arch/PowerPC/PPCInstPrinter.c:410`、`PPCMapping.c:536` | 32 位模式 `& 0xffffffff`，64 位 mod 2^64 | 是 | 是 |
| RISC-V | `arch/RISCV/RISCVInstPrinter.c:148`、`RISCVMapping.c:143-156` | 文本：RV32 截 32 位；**detail：永不截断** | **否（RV32）** | 是（头文件注释未列） |
| MIPS32 | `arch/Mips/MipsInstPrinter.c:325`、`MipsMapping.c:351` | **不截断** | 是（但都错） | 否 |
| LoongArch32 | `arch/LoongArch/LoongArchInstPrinter.c:121` | **不截断** | 是（但都错） | 否 |
| HPPA(32) | `arch/HPPA/HPPAInstPrinter.c:622` | **不截断** | detail 存的是偏移，文本是绝对值（设计不同） | 否 |
| TMS320C64x | `arch/TMS320C64x/TMS320C64xDisassembler.c:255` | **不截断**（mod 2^64） | — | 否 |
| TriCore | `arch/TriCore/TriCoreInstPrinter.c:259,387` | 文本 `wrapping_u32`，**detail 为未截断 int64** | **否** | 否 |
| Xtensa | `arch/Xtensa/XtensaMapping.c:194`（L32R） | 不截断；分支指令永远只打印偏移 | — | 否 |
| SH | `arch/SH/SHDisassembler.c:1166,1255` | 经 `uint32_t` 形参截到 32 位 | 是 | 否 |
| Sparc | `arch/Sparc/SparcDisassembler.c:120-141` + `SparcInstPrinter.c:188` | 计算 mod 2^64，打印时 `(int)` 截 32 位 | — | 否 |
| SystemZ | `arch/SystemZ/SystemZDisassembler.c:314` | mod 2^64 | 是 | 否 |
| Alpha | `arch/Alpha/AlphaInstPrinter.c:62-72` | mod 2^64 | 是 | 否 |
| M68K | `arch/M68K/M68KInstPrinter.c:572` | `uint32_t pc` 自然回绕 32 位 | detail 存原始位移 | 否 |
| M680X | `arch/M680X/M680XDisassembler.c:1241,1252` | `uint16_t` 自然回绕 16 位 | 是 | 否 |
| MOS65XX | `arch/MOS65XX/MOS65XXDisassembler.c:239,253` | `& 0xffff` | 是 | 否 |
| ARC / BPF / XCore | `ARCInstPrinter.c:138` 等 | 不计算目标，永远只打印原始偏移 | — | 否（行为等同 offset-only） |

## 二、确认的问题

### A. 有符号溢出 / 实现定义行为（潜在 UB）

1. **TriCore** `arch/TriCore/TriCoreInstPrinter.c:259`：
   ```c
   #define DISP_SEXT_2ALIGN(N) ((int64_t)(MI->address) + SignExtend64(disp, N) * 2)
   ```
   `MI->address` 是用户传入的 `uint64_t`。当 `address >= 2^63` 时，`(int64_t)` 强转
   是实现定义行为；当 `address` 接近 `INT64_MAX` 时，有符号加法溢出是未定义行为。
   TriCore 是 32 位 MCU 架构，本应先把地址掩到 32 位再做无符号运算。

2. **Xtensa L32R** `arch/Xtensa/XtensaMapping.c:194`：
   ```c
   Value = (((int64_t)MI->address + 3) & ~0x3) + InstrOff;
   ```
   同样的问题：`address` 接近 `INT64_MAX` 时有符号加法溢出（UB）；结果也不截断到
   Xtensa 的 32 位地址空间。

x86 的 `MCOperand_getImm(Op) + size + MI->address`（`X86IntelInstPrinter.c:883`）
由于 `MI->address` 是 `uint64_t`，整个求值按无符号进行，是定义良好的 mod 2^64
回绕，不属于 UB，但赋回 `int64_t imm` 依赖实现定义的转换。

### B. 32 位架构不截断（与其他 32 位架构回绕结果不一致）

以下样本中，ARM/PPC32/RISC-V32/SH/M68K 都回绕到 32 位，而这几个架构输出了
超出 32 位地址空间的目标：

| 样本 | 地址 | 实际输出 | 32 位回绕应为 |
|---|---|---|---|
| MIPS32 `b +1`：`01 00 00 10`（LE） | `0xfffffffc` | `b 0x100000004`，detail imm `0x100000004` | `0x4` |
| LoongArch32 `b +0x1000`：`00 04 00 50` | `0xfffffffc` | `b 0x100000000`，detail imm `0x100000000` | `0x0` |
| HPPA `b,l +8`：`e8 00 00 08`（BE） | `0xfffffffc` | `b,l 0x100000008` | `0x8` |
| TMS320C64x `b`：`e1 ff ff 13`（BE） | `0xffffffe0` | `b 0x1000fffd8` | `0xfffd8` |
| x86-16 `jmp +5`：`e9 05 00` | `0xfffc` | `jmp 0x10004`，detail imm `0x10004` | `0x0004`（IP 为 16 位） |

另外 MIPS 的 `printJumpOperand`（`MipsInstPrinter.c:319`）用
`MI->address & ~0x0fffffff` 取区域基址：MIPS32 下若用户传入大于 4 GiB 的地址，
高位会泄漏进 `j` 目标，与 32 位语义（`PC[31:28]`）不符。

### C. 文本与 detail 不一致

1. **RISC-V 32 位**：`RISCVInstPrinter.c:156-158` 打印时按模式截断，但
   `RISCVMapping.c:147-149` 的 detail imm 只做 `imm += MI->address`，永不截断。
   样本 `ef 00 40 00`（`jal +8`）@ `0xfffffffc`：文本 `jal 0`，
   detail imm `0x100000000`。同一条指令两个答案。
2. **TriCore**：文本经 `wrapping_u32` 截断（`TriCoreInstPrinter.c:401`），
   `fill_imm`（`:67`）却把未截断的 `int64_t res` 写进 detail。
   样本 `1d 04 00 00`（`j disp24`）@ `0xfffffffc`：文本 `j #0x7fffd`，
   detail imm `0x10007fffc`。

### D. offset-only 模式（`CS_OPT_ONLY_OFFSET_BRANCH`）的不一致

- `include/capstone/capstone.h:394` 注释只列 "ARM, PPC, AArch64"，但 RISC-V
  同样响应该选项（`RISCVInstPrinter.c:155`），文档与实现不符。
- offset 模式下 detail 语义分裂：AArch64 的 detail imm 始终是绝对目标
  （`AArch64Mapping.c:1506-1561`，不看该选项）；ARM 走
  `ARMInstPrinter.c:161` 的提前返回后，detail imm 变成原始偏移。同一选项下
  两个架构的 detail 给出不同种类数值。
- MIPS、LoongArch、SystemZ、Sparc、SH、TMS320C64x、HPPA、Alpha 完全不支持
  该选项（永远输出绝对目标）；ARC、BPF、XCore、Xtensa 分支则永远只输出偏移，
  用户无法统一控制。

### E. 回绕行为正确、无需改动的架构

x86-64（mod 2^64，与 RIP 相对语义一致）、x86-32、ARM/Thumb、AArch64、PPC、
RISC-V 文本、SH、M68K、M680X、MOS65XX、SystemZ、Alpha、Sparc（打印侧截断）。
这些可作为统一语义的对照基准。

## 三、修复取舍论证

**方案 1：全部按架构地址宽度回绕（mod 2^N，N = 模式位宽）。**
与硬件语义一致（32 位 CPU 的 PC 就是 32 位），各架构结果可比。代价是改变
MIPS32/LoongArch32/HPPA/TMS320C64x/x86-16 长期以来的输出，下游若依赖未截断值
做回绕检测会受影响；且属于行为变更，需要开发者在 `docs/cs_v6_release_guide.md`
中记录。

**方案 2：全部不截断，统一 mod 2^64。**
实现最简单、信息无损，但与 32 位硬件语义相悖，且同样要改变 ARM/PPC/RISC-V 等
已经正确的架构，回归面最大，不可取。

**方案 3（建议）：分层修复。**
1. 先修正确性缺陷，不改变正常路径输出：
   - TriCore / Xtensa 的有符号运算改为无符号（先掩地址到架构宽度再相加），消除 UB；
   - RISC-V32 与 TriCore 的 detail imm 与文本对齐（同一处计算、同一处截断），
     消除"一条指令两个目标"的 split-brain。
2. 再统一 32 位截断语义（方案 1 的子集）：MIPS32、LoongArch32、HPPA32、
   TMS320C64x、x86-16 按模式截断到地址宽度。这批改动有明确硬件依据，且与
   ARM/PPC/RISC-V/SH/M68K 的现有行为对齐，回归风险集中在少数架构的期望值更新。
3. offset-only 模式：把 RISC-V 补进 `capstone.h:394` 的注释（文档由开发者撰写），
   并统一规定 detail imm 在该模式下的语义（建议始终保持绝对目标，与 AArch64
   现状一致，因为 detail 面向程序化消费，绝对地址更有用；文本已表达偏移）。

不建议为"是否截断"新增全局选项：现有 `CS_OPT_ONLY_OFFSET_BRANCH` 已提供偏移视图，
再加一个截断开关只会让矩阵更复杂。

## 四、复现说明

```
make -j            # 构建 libcapstone 与 cstool
./cstool/cstool mipsel "01 00 00 10" 0xfffffffc        # b 0x100000004（不截断）
./cstool/cstool loongarch32 "00 04 00 50" 0xfffffffc   # b 0x100000000（不截断）
./cstool/cstool x16 "e9 05 00" 0xfffc                  # jmp 0x10004（未截到 16 位）
./cstool/cstool arm "00 00 00 ea" 0xfffffffc           # b 4（正确回绕，对照）
./cstool/cstool riscv32 "ef 00 40 00" 0xfffffffc       # jal 0（文本截断；detail 为 0x100000000）
./cstool/cstool tc160 "1d 04 00 00" 0xfffffffc         # j #0x7fffd（detail 为 0x10007fffc）
./cstool/cstool tms320c64x "e1 ff ff 13" 0xffffffe0    # b 0x1000fffd8（不截断）
./cstool/cstool hppa20be "e8 00 00 08" 0xfffffffc      # b,l 0x100000008（不截断）
./cstool/cstool x64 "e9 05 00 00 00" 0xfffffffffffffffc # jmp 6（正确 mod 2^64，对照）
./cstool/cstool aarch64 "01 00 00 14" 0xfffffffffffffffc # b 0（正确 mod 2^64，对照）
```

detail 数值用开启 `CS_OPT_DETAIL` 后读取 `x86.operands[i].imm` /
`riscv.operands[i].imm` / `tricore.operands[i].imm` 等字段验证。
