# x86Tester

Generates ground truth test vectors for x86-64 instructions by executing each
encoding on real hardware and recording the resulting register and flag state.
It is not a model and not an emulator: every result is what the silicon actually
produced, including values that the architecture leaves undefined.

For each instruction encoding the tool sets a known input register and flag
state, runs the single instruction inside a debugger harness, and reads back the
output. Inputs are swept so that every reachable output bit is exercised, and
deterministically impossible bits are modeled so generation converges instead of
burning the full input budget. The harness uses the Windows debug API on Windows
and ptrace on Linux.

A generated dataset is published at
https://huggingface.co/datasets/BinPrey/x86-instruction-test-vectors.

## Building

The build is driven by cmkr: edit `cmake.toml`, and `CMakeLists.txt` is generated
from it. A C++23 compiler is required (`std::print` needs GCC 14 or a recent MSVC)
and CMake 3.25 or newer.

Windows:

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

Linux:

```
cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=gcc-14 -DCMAKE_CXX_COMPILER=g++-14 -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Zydis, sfl and GoogleTest are fetched automatically during configuration.

## Running

```
x86Tester-cli [options] [mnemonic ...]
```

| Option | Meaning |
| --- | --- |
| `<mnemonic>` | Generate the named mnemonic, for example `lea add`. Default is all supported instructions. |
| `--isa <ext>` | Generate all mnemonics of an ISA extension, for example `SSE2`, `BMI1`. |
| `--category <cat>` | Generate all mnemonics of a category, for example `BINARY`, `SSE`. |
| `--exclude <mnemonic>` | Exclude a mnemonic from the selection. |
| `--out <dir>` | Output directory (default `testdata`). |
| `--force` | Regenerate even if the output file already exists. |
| `--list` | List the selected mnemonics and exit. |
| `--stop-on-impossible` | Stop cleanly at the first impossible target. |

Output is written to a per CPU subfolder of the output directory, named by the
processor brand string together with its family, model and stepping, for example
`testdata/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10/`. One text file is
produced per mnemonic.

Generating the full instruction set spawns one debuggee process per worker and
can exhaust memory or process count if something goes wrong. Use the wrapper
scripts for full runs: `run-gen.ps1` on Windows runs the tool inside a Job Object
capped at 10 GB and a bounded process count, and `run-gen.sh` on Linux does the
same with a cgroup v2 memory and pids cap. Both fail closed if the caps cannot be
applied.

## Output format

Each file is plain text and describes one mnemonic. It starts with a value pool
and is followed by the tested encodings.

```
data:<N>
#<hex 0>
#<hex 1>
...
#<hex N-1>
instr:0x<address>;#<encoding>;<asm>;<count>;in=<in schema>;out=<out schema>
<row 0>
<row 1>
...
instr:...
...
```

The first line `data:<N>` gives the number of pooled values. The next `N` lines
each hold one value as `#<hex>`, referenced elsewhere by its zero based index.
Values are hex of the raw little endian register or flag bytes, so the first byte
pair is the lowest byte. A flags value of `01000000` is therefore `0x00000001`,
the carry flag.

Each tested encoding has a header line followed by `count` rows:

- `address`: the hex address the instruction executed at. It is a fixed base for
  the whole run, so any address dependent result already has its output recorded.
- `encoding`: the instruction bytes as hex.
- `asm`: the disassembly.
- `count`: the number of rows that follow.
- `in schema`, `out schema`: comma separated register names that are read and
  written, with `flags` appended when flags are part of the state. The order
  matches the values in each row.

A row is `<inputs>|<outputs>`. The inputs are comma separated pool indices, one
per name in the input schema, in order. The outputs are either comma separated
pool indices, one per name in the output schema, or `!<exception>` when the
instruction faulted, for example `!INT_DIVIDE_ERROR` or `!INT_OVERFLOW`.

### Example

```
data:6
#0000CCCCCCCCCCCC
#00000000CCCCCCCC
#0000000000000000
#FFFFFFFFCCCCCCCC
#FFFFFFFF00000000
#FFFFFFFFFFFFFFFF
instr:0x4000001;#0FC8;bswap eax;2;in=rax;out=rax
1|2
3|4
```

This is `bswap eax` (encoding `0F C8`) with two cases. The first row reads
`rax = pool[1] = 00000000CCCCCCCC`, so `eax` is `0`, and writes
`rax = pool[2] = 0000000000000000`. The second row reads
`rax = pool[3] = FFFFFFFFCCCCCCCC`, so `eax` is `0xFFFFFFFF`, byte swaps it, and
writes `rax = pool[4] = FFFFFFFF00000000`.
