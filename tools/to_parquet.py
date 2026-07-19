import argparse
import json
import os
import re
import pyarrow as pa
import pyarrow.parquet as pq

SCHEMA = pa.schema([
    ("address", pa.uint64()),
    ("asm", pa.string()),
    ("mnemonic", pa.string()),
    ("encoding", pa.string()),
    ("inputs", pa.string()),
    ("outputs", pa.string()),
    ("exception", pa.string()),
])


def cpu_metadata(name):
    m = re.match(r"^(.*)_f(\d+)m(\d+)s(\d+)$", name)
    if not m:
        return {"cpu": name}
    return {
        "cpu": m.group(1),
        "family": m.group(2),
        "model": m.group(3),
        "stepping": m.group(4),
    }


def read_cpu(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        first = f.readline().rstrip("\r\n")
        if first != "cpu:":
            return None
        return f.readline().rstrip("\r\n")


def parse_file(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    base = 0
    if base < len(lines) and lines[base].startswith("cpu:"):
        base += 2
    if base >= len(lines) or not lines[base].startswith("data:"):
        return
    pool_count = int(lines[base][5:])
    pool = [lines[base + 1 + k][1:] for k in range(pool_count)]
    i = base + 1 + pool_count
    n = len(lines)
    while i < n:
        line = lines[i]
        i += 1
        if not line.startswith("instr:"):
            continue
        parts = line.split(";")
        if len(parts) < 6:
            continue
        address = int(parts[0][len("instr:"):], 16)
        encoding = parts[1][1:]
        asm = parts[2]
        count = int(parts[3])
        in_schema = [s for s in parts[4][3:].split(",") if s]
        out_schema = [s for s in parts[5][4:].split(",") if s]

        def resolve(name):
            m = re.match(r"^\[(\d+)\]$", name)
            if m:
                return "[" + pool[int(m.group(1))] + "]"
            return name

        for _ in range(count):
            row = lines[i]
            i += 1
            in_part, out_part = row.split("|", 1)
            inputs = {}
            for name, idx in zip(in_schema, [v for v in in_part.split(",") if v]):
                inputs[resolve(name)] = pool[int(idx)]
            outputs = {}
            exception = None
            if out_part.startswith("!"):
                exception = out_part[1:]
            else:
                for name, idx in zip(out_schema, [v for v in out_part.split(",") if v]):
                    outputs[resolve(name)] = pool[int(idx)]
            yield asm, encoding, address, inputs, outputs, exception


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_dir")
    ap.add_argument("output_dir", nargs="?")
    args = ap.parse_args()

    txts = sorted(fn for fn in os.listdir(args.input_dir) if fn.endswith(".txt"))
    if not txts:
        raise SystemExit(f"no .txt files in {args.input_dir}")

    cpu = None
    for fn in txts:
        c = read_cpu(os.path.join(args.input_dir, fn))
        if c is None:
            raise SystemExit(f"{fn}: missing cpu: block")
        if cpu is None:
            cpu = c
        elif c != cpu:
            raise SystemExit(f"cpu mismatch: {fn} has '{c}', expected '{cpu}'")

    out_dir = args.output_dir if args.output_dir else args.input_dir
    os.makedirs(out_dir, exist_ok=True)
    output = os.path.join(out_dir, cpu + ".parquet")

    schema = SCHEMA.with_metadata(cpu_metadata(cpu))
    writer = pq.ParquetWriter(output, schema, compression="zstd")
    total = 0
    for fn in txts:
        mnemonic = fn[:-4]
        mnems, addrs, asms, encs, ins, outs, excs = [], [], [], [], [], [], []
        for asm, encoding, address, inputs, outputs, exception in parse_file(os.path.join(args.input_dir, fn)):
            mnems.append(mnemonic)
            addrs.append(address)
            asms.append(asm)
            encs.append(encoding)
            ins.append(json.dumps(inputs))
            outs.append(json.dumps(outputs))
            excs.append(exception)
        if not mnems:
            continue
        batch = pa.table({
            "address": pa.array(addrs, pa.uint64()),
            "asm": pa.array(asms, pa.string()),
            "mnemonic": pa.array(mnems, pa.string()),
            "encoding": pa.array(encs, pa.string()),
            "inputs": pa.array(ins, pa.string()),
            "outputs": pa.array(outs, pa.string()),
            "exception": pa.array(excs, pa.string()),
        }, schema=schema)
        writer.write_table(batch)
        total += len(mnems)
    writer.close()
    print(f"{total} rows from {args.input_dir} -> {output}")


if __name__ == "__main__":
    main()
