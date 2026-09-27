"""Extrai os numeros dos logs da suite de benchmark e imprime tabelas em Markdown."""
import re, sys

def parse(path):
    t = open(path, encoding="utf-8", errors="replace").read()
    d = {"path": path}
    d["alvo"]   = re.search(r"Alvo \(CONFIG_IDF_TARGET\)\s*: (\S+)", t).group(1)
    d["idf"]    = re.search(r"ESP-IDF\s*: (\S+)", t).group(1)
    d["core"]   = re.search(r"Core arduino-esp32\s*: (\S+)", t).group(1)
    d["chip"]   = re.search(r"Chip\s*: (.+?), CPU", t).group(1)
    d["sketch"] = int(re.search(r"sketch (\d+) bytes", t).group(1))
    d["part"]   = int(re.search(r"espaco livre para sketch (\d+)", t).group(1))
    cold = re.findall(r"^\s+(Ascon-128a cifra|Ascon-128a decifra|AES-128-GCM cifra|AES-128-GCM decifra)\s+(\d+) ciclos \(([\d.]+) us\)", t, re.M)
    d["cold"] = {k: (int(c), float(us)) for k, c, us in cold[:4]}
    d["heap"] = {}
    for m in re.finditer(r"^\s+(\d+) B\s+(Ascon-128a cifra|Ascon-128a decifra|AES-128-GCM cifra|AES-128-GCM decifra)\s+heap antes (\d+) \| menor durante (\d+) \| depois (\d+) \(delta (-?\d+)\) \| (\d+) amostras \| (.+)$", t, re.M):
        d["heap"][(int(m.group(1)), m.group(2).strip())] = (int(m.group(3)), int(m.group(4)), int(m.group(5)), int(m.group(6)), int(m.group(7)), m.group(8).strip())
    d["stack"] = {m.group(1).strip(): int(m.group(2)) for m in re.finditer(r"^\s+(Ascon-128a cifra|Ascon-128a decifra|AES-128-GCM cifra|AES-128-GCM decifra)\s+marca inicial \d+ \| marca final \d+ \| consumo da operacao (\d+) bytes", t, re.M)}
    # secao 3
    s3 = t[t.index("[3] Tempo"):t.index("[4] Tempo")]
    d["ascon"] = {}
    for blk in re.finditer(r"^\s+(\d+) B cifra\s+\.+\n\s+\d+ B decifra\s+\.+\n\s+cifra  : piso min (\d+).*?\n\s+decifra: piso min (\d+).*?\n\s+cifra com interrupcoes desligadas, 1 execucao: piso (\d+)", s3, re.M):
        d["ascon"][int(blk.group(1))] = (int(blk.group(2)), int(blk.group(3)), int(blk.group(4)))
    d["fit"] = re.findall(r"(cifra  |decifra): parcela fixa extrapolada (\d+) \+ ([\d.]+) ciclos", s3)
    d["gran"] = re.search(r"cifra: 2 B - 0 B = (-?\d+) ciclos \((\d+) por byte\) \| 23 B - 16 B = (-?\d+) ciclos \((\d+) por byte\) \| 32 B - 16 B = (-?\d+)", s3).groups()
    # secao 4
    s4 = t[t.index("[4] Tempo"):t.index("[5] Comparativo")]
    d["classes"] = re.findall(r"^\s+(\d+) B\n(?:.*\n){5}\s+entre classes: pisos de (\d+) a (\d+) \(spread (\d+) ciclos\) \| medias de ([\d.]+) a ([\d.]+) \(spread ([\d.]+) ciclos", s4, re.M)
    d["class_rows"] = {}
    for blk in re.finditer(r"^\s+(\d+) B\n((?:\s+\S.*: piso \d+ \| media [\d.]+ \| max \d+ \| desvio [\d.]+ \| spread \d+ ciclos\n){5})", s4, re.M):
        rows = {}
        for line in blk.group(2).strip().splitlines():
            m = re.match(r"\s*(.+?)\s*: piso (\d+) \| media ([\d.]+) \| max (\d+) \| desvio ([\d.]+)", line)
            rows[m.group(1).strip()] = (int(m.group(2)), float(m.group(3)), int(m.group(4)), float(m.group(5)))
        d["class_rows"][int(blk.group(1))] = rows
    d["class_sd"] = re.findall(r"^\s+rampa\s+: piso \d+ \| media [\d.]+ \| max (\d+) \| desvio ([\d.]+)", s4, re.M)
    # secao 5
    s5 = t[t.index("[5] Comparativo"):t.index("[6] O AES")]
    d["cmp"] = {}
    for blk in re.finditer(r"^\s+(\d+) B cifra\s+\.+\n\s+\d+ B decifra\s+\.+\n\s+cifra:\n\s+Ascon-128a : piso min (\d+).*?\n\s+AES-128-GCM: piso min (\d+) \| piso max (\d+).*?execucoes no piso (\d+)/100.*?\n\s+razao AES/Ascon: min ([\d.]+) \| max ([\d.]+) \| media ([\d.]+).*?\n\s+decifra:\n\s+Ascon-128a : piso min (\d+).*?\n\s+AES-128-GCM: piso min (\d+) \| piso max (\d+).*?execucoes no piso (\d+)/100.*?\n\s+razao AES/Ascon: min ([\d.]+) \| max ([\d.]+) \| media ([\d.]+)", s5, re.M):
        g = blk.groups()
        d["cmp"][int(g[0])] = dict(asconE=int(g[1]), aesE=int(g[2]), aesEmax=int(g[3]), aesEat=int(g[4]), ratioE=float(g[7]),
                                   asconD=int(g[8]), aesD=int(g[9]), aesDmax=int(g[10]), aesDat=int(g[11]), ratioD=float(g[14]))
    d["wins"] = re.search(r"Ascon mais rapido que o AES-GCM em (\d+)/(\d+)", s5).groups()
    d["gcm_gran"] = re.search(r"cifra: 2 B - 0 B = (-?\d+) \| 16 B - 2 B = (-?\d+) \| 23 B - 16 B = (-?\d+) \| 32 B - 23 B = (-?\d+)", s5).groups()
    # secao 6
    s6 = t[t.index("[6] O AES"):]
    d["macros"] = re.findall(r"^\s+(SOC_AES_SUPPORT_GCM|SOC_AES_SUPPORT_DMA|CONFIG_MBEDTLS_HARDWARE_AES|CONFIG_MBEDTLS_HARDWARE_GCM)\s*: (\w+)", s6, re.M)
    d["paths"] = {m.group(1).strip(): (int(m.group(2)), int(m.group(3)), int(m.group(4)), float(m.group(5)), float(m.group(6))) for m in re.finditer(r"^\s+(AES-CTR \(so cifra AES\)|AES-GCM \(cifra \+ GHASH\)|Ascon-128a \(software\))\s*: 16 B\s+(\d+) \| 32 B\s+(\d+) \| 64 B\s+(\d+) \| por bloco\s+([\d.]+) ciclos \| linearidade ([\d.]+)%", s6, re.M)}
    d["ghash"] = float(re.search(r"GHASH por bloco \(GCM - CTR\)\s*: ([\d.]+) ciclos", s6).group(1))
    d["summary"] = re.search(r"Mensagem tipica de 23 B.*?Ascon cifra (\d+) ciclos \(([\d.]+) us\) \| AES-GCM cifra (\d+) ciclos \(([\d.]+) us\) \| razao ([\d.]+)", s6).groups()
    d["counts"] = re.search(r"Problemas: (\d+) \| Ressalvas: (\d+)", s6).groups()
    d["verdict"] = "OK" if "BENCHMARK OK" in s6 else "COM PROBLEMAS"
    return d

def mhz_us(c): return c / 240.0

if __name__ == "__main__":
    logs = [parse(p) for p in sys.argv[1:]]
    names = {"esp32": "ESP32 clássico", "esp32s3": "Heltec (ESP32-S3)"}
    print("## Identificação")
    for d in logs:
        print(f"- **{names[d['alvo']]}**: {d['chip']}, core {d['core']}, ESP-IDF {d['idf']}, sketch {d['sketch']:,} B, partição {d['part']:,} B, veredito {d['verdict']}, problemas {d['counts'][0]}, ressalvas {d['counts'][1]}".replace(",", "."))
    print("\n## Cifra: piso em ciclos (µs), por tamanho\n")
    print("| Bytes | " + " | ".join(f"Ascon {names[d['alvo']]} | AES-GCM {names[d['alvo']]} | razão" for d in logs) + " |")
    print("|---|" + "---|---|---|" * len(logs))
    for size in [0, 2, 16, 23, 32, 64]:
        row = [str(size)]
        for d in logs:
            c = d["cmp"][size]; a = d["ascon"][size][0]
            row += [f"{a:,} ({mhz_us(a):.1f})".replace(",", "."), f"{c['aesE']:,} ({mhz_us(c['aesE']):.1f})".replace(",", "."), f"{c['ratioE']:.2f}"]
        print("| " + " | ".join(row) + " |")
    print("\n## Decifra: piso em ciclos, por tamanho\n")
    print("| Bytes | " + " | ".join(f"Ascon {names[d['alvo']]} | AES-GCM {names[d['alvo']]} | razão" for d in logs) + " |")
    print("|---|" + "---|---|---|" * len(logs))
    for size in [0, 2, 16, 23, 32, 64]:
        row = [str(size)]
        for d in logs:
            c = d["cmp"][size]; a = d["ascon"][size][1]
            row += [f"{a:,}".replace(",", "."), f"{c['aesD']:,}".replace(",", "."), f"{c['ratioD']:.2f}"]
        print("| " + " | ".join(row) + " |")
    print("\n## Modelo linear e decomposição (ciclos por bloco de 16 B)\n")
    print("| | " + " | ".join(names[d['alvo']] for d in logs) + " |")
    print("|---|" + "---|" * len(logs))
    rows = [("Ascon cifra: parcela fixa", lambda d: d['fit'][0][1]), ("Ascon cifra: por bloco", lambda d: d['fit'][0][2]),
            ("Ascon decifra: parcela fixa", lambda d: d['fit'][1][1]), ("Ascon decifra: por bloco", lambda d: d['fit'][1][2]),
            ("AES-CTR por bloco", lambda d: f"{d['paths']['AES-CTR (so cifra AES)'][3]:.0f}"),
            ("AES-CTR 16 B (custo total)", lambda d: str(d['paths']['AES-CTR (so cifra AES)'][0])),
            ("AES-GCM por bloco", lambda d: f"{d['paths']['AES-GCM (cifra + GHASH)'][3]:.0f}"),
            ("GHASH por bloco (GCM − CTR)", lambda d: f"{d['ghash']:.0f}"),
            ("Bloco parcial: 2−0 B / 23−16 B", lambda d: f"{d['gran'][0]} / {d['gran'][2]}"),
            ("AES-GCM 2−0 / 23−16 / 32−23 B", lambda d: f"{d['gcm_gran'][0]} / {d['gcm_gran'][2]} / {d['gcm_gran'][3]}"),
            ("Ascon venceu", lambda d: f"{d['wins'][0]}/{d['wins'][1]}")]
    for label, fn in rows:
        print(f"| {label} | " + " | ".join(str(fn(d)) for d in logs) + " |")
    print("\n## Memória\n")
    print("| | " + " | ".join(names[d['alvo']] for d in logs) + " |")
    print("|---|" + "---|" * len(logs))
    for op in ["Ascon-128a cifra", "Ascon-128a decifra", "AES-128-GCM cifra", "AES-128-GCM decifra"]:
        cells = []
        for d in logs:
            verdicts = {d["heap"][(s, op)][5] for s in [0, 2, 16, 23, 32, 64]}
            drop = max(d["heap"][(s, op)][0] - d["heap"][(s, op)][1] for s in [0, 2, 16, 23, 32, 64])
            samples = min(d["heap"][(s, op)][4] for s in [0, 2, 16, 23, 32, 64])
            cells.append(f"heap: {'sem alocação' if verdicts == {'sem alocacao'} else f'transitória de {drop} B'} (≥{samples} amostras); pilha {d['stack'][op]} B")
        print(f"| {op} | " + " | ".join(cells) + " |")
    print("\n## Tempo constante (5 classes, interrupções desligadas)\n")
    for d in logs:
        for size, fmin, fmax, fsp, mmin, mmax, msp in d["classes"]:
            print(f"- {names[d['alvo']]}, {size} B: pisos {fmin}–{fmax} (spread {fsp}), médias {mmin}–{mmax} (spread {msp} ciclos)")
        print(f"  desvio dentro da execução (rampa): {', '.join(sd for _, sd in d['class_sd'])} ciclos; máximo {', '.join(mx for mx, _ in d['class_sd'])}")
    print("\n## Primeira chamada (cache fria, 16 B)\n")
    for d in logs:
        print(f"- {names[d['alvo']]}: " + "; ".join(f"{k} {v[0]:,} ciclos ({v[1]:.0f} µs)".replace(",", ".") for k, v in d["cold"].items()))
    print("\n## Macros\n")
    for d in logs:
        print(f"- {names[d['alvo']]}: " + ", ".join(f"{m} {v}" for m, v in d["macros"]))
