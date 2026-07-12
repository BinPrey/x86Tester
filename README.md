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

## Test data and contributing

A run writes plain text locally, one file per mnemonic, into a per CPU subfolder
of the output directory (see Running below). The collected vectors from many
processors are stored together as a dataset on Hugging Face at
https://huggingface.co/datasets/BinPrey/x86-instruction-test-vectors.

To contribute a run, convert it to Parquet and open a pull request against that
dataset. The scripts in `tools/` need `pyarrow`, and `huggingface_hub` for
uploading:

```
pip install pyarrow huggingface_hub
```

Pack a per CPU output folder into a single Parquet file with the columns
`address`, `asm`, `mnemonic`, `encoding`, `inputs`, `outputs` and `exception`. The
output filename and the `cpu`, `family`, `model` and `stepping` metadata are taken
from the `cpu:` block inside the text files, which every file in the folder must
share. The second argument is an optional output folder; omit it to write the
Parquet file next to the text files:

```
python tools/to_parquet.py testdata/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10 data
```

That writes `data/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10.parquet`. The
inverse rebuilds the text files from a Parquet file, which is useful to check a
round trip:

```
python tools/to_raw.py data/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10.parquet testdata_roundtrip
```

Log in once with a token that has write access, then upload with `--create-pr`,
which pushes to a new branch and opens the request instead of committing to
`main`:

```
hf auth login
hf upload BinPrey/x86-instruction-test-vectors data/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10.parquet data/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10.parquet --repo-type dataset --create-pr
```

Finally, add the processor to the dataset index so it appears as its own subset in
the viewer. The dataset's `README.md` carries a `configs:` block in its YAML front
matter with one entry per CPU; add yours in the same pull request, pointing at the
file you uploaded:

```yaml
- config_name: Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10
  data_files:
  - split: train
    path: data/Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10.parquet
```

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

## Output format

Each file is plain text and describes one mnemonic. It opens with the CPU it was
produced on, then a value pool, followed by the tested encodings.

```
cpu:
<cpu name>
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

The `cpu:` line is followed by the processor name in the same
`<brand>_f<family>m<model>s<stepping>` form as the output subfolder. The
`data:<N>` line then gives the number of pooled values. The next `N` lines
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
  written, with `flags` appended when flags are part of the state. Names use the
  Zydis spelling, including x87 registers such as `st0`, `x87status` and
  `x87control`. The order matches the values in each row.

A row is `<inputs>|<outputs>`. The inputs are comma separated pool indices, one
per name in the input schema, in order. The outputs are either comma separated
pool indices, one per name in the output schema, or `!<exception>` when the
instruction faulted, for example `!INT_DIVIDE_ERROR` or `!INT_OVERFLOW`.

For x87 arithmetic that rounds (`fadd`, `fmul`, `fdiv`, `fsqrt`, `frndint` and
similar), `x87control` is provided as an input and swept over every rounding and
precision control combination, so each row records the result and `x87status`
for one rounding and precision mode. Instructions that write the control word
(`fldcw`, `fninit`, `fldenv`, `frstor`) record it in the output schema instead.

### Example

```
cpu:
Intel_R_Core_TM_i7_8700K_CPU_3_70GHz_f6m158s10
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
