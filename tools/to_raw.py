import argparse
import json
import os
import re
import pyarrow.parquet as pq


def cpu_folder(meta):
    if not meta:
        return None

    def get(key):
        v = meta.get(key.encode())
        return v.decode() if v is not None else None

    cpu = get("cpu")
    if cpu is None:
        return None
    family, model, stepping = get("family"), get("model"), get("stepping")
    if family and model and stepping:
        return "{}_f{}m{}s{}".format(cpu, family, model, stepping)
    return cpu


def build_file(rows):
    pool = []
    pool_index = {}

    def intern(hexval):
        idx = pool_index.get(hexval)
        if idx is None:
            idx = len(pool)
            pool_index[hexval] = idx
            pool.append(hexval)
        return idx

    def schema_token(name):
        m = re.match(r"^\[(.+)\]$", name)
        if m:
            return "[{}]".format(intern(m.group(1)))
        return name

    groups = {}
    order = []
    for asm, encoding, address, inputs, outputs, exception in rows:
        key = (address, encoding)
        g = groups.get(key)
        if g is None:
            g = {"asm": asm, "address": address, "encoding": encoding, "rows": []}
            groups[key] = g
            order.append(key)
        g["rows"].append((inputs, outputs, exception))

    body = []
    for key in order:
        g = groups[key]
        grows = g["rows"]

        in_schema = list(grows[0][0].keys())
        out_schema = []
        for inputs, outputs, exception in grows:
            if exception is None:
                out_schema = list(outputs.keys())
                break

        in_schema_str = ",".join(schema_token(k) for k in in_schema)
        out_schema_str = ",".join(schema_token(k) for k in out_schema)

        body.append("instr:0x{:X};#{};{};{};in={};out={}".format(
            g["address"], g["encoding"], g["asm"], len(grows), in_schema_str, out_schema_str))

        for inputs, outputs, exception in grows:
            left = ",".join(str(intern(inputs[name])) for name in in_schema)
            if exception is not None:
                right = "!" + exception
            else:
                right = ",".join(str(intern(outputs[name])) for name in out_schema)
            body.append(left + "|" + right)

    return pool, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output_dir")
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    table = pq.read_table(args.input)
    folder = cpu_folder(table.schema.metadata)
    mnem = table.column("mnemonic").to_pylist()
    addr = table.column("address").to_pylist()
    asm = table.column("asm").to_pylist()
    enc = table.column("encoding").to_pylist()
    ins = table.column("inputs").to_pylist()
    outs = table.column("outputs").to_pylist()
    excs = table.column("exception").to_pylist()

    by_mnem = {}
    order = []
    for i in range(len(mnem)):
        m = mnem[i]
        rows = by_mnem.get(m)
        if rows is None:
            rows = []
            by_mnem[m] = rows
            order.append(m)
        rows.append((asm[i], enc[i], addr[i], json.loads(ins[i]), json.loads(outs[i]), excs[i]))

    total = 0
    for m in order:
        rows = by_mnem[m]
        pool, body = build_file(rows)
        with open(os.path.join(args.output_dir, m + ".txt"), "w", encoding="utf-8", newline="\n") as f:
            if folder:
                f.write("cpu:\n{}\n".format(folder))
            f.write("data:{}\n".format(len(pool)))
            for h in pool:
                f.write("#{}\n".format(h))
            for line in body:
                f.write(line + "\n")
        total += len(rows)
    print("{} rows -> {} ({} mnemonics)".format(total, args.output_dir, len(order)))


if __name__ == "__main__":
    main()
