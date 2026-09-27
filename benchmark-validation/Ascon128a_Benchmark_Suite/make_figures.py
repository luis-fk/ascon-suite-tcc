#!/usr/bin/env python3
"""Gera as figuras do Cap5 a partir dos dois logs da suite.

Uso: python3 make_figures.py bench-results-esp32.txt bench-results-heltec.txt <pasta de saida>

Cada figura sai em PDF (para o LaTeX) e PNG (para conferir). Os numeros vem
inteiros dos logs, via parse_results.py; nada e recalculado aqui alem de
subtracoes simples (media - piso, GCM - CTR).
"""
import os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
from parse_results import parse

# Okabe-Ito (Wong, 2011), subconjunto com contraste sobre branco.
BLUE, VERMILLION, GREEN, PURPLE, BLACK, GRAY = "#0072B2", "#D55E00", "#009E73", "#CC79A7", "#000000", "#777777"
SIZES = [0, 2, 16, 23, 32, 64]
BOARD = {"esp32": "ESP32 clássico (Xtensa LX6)", "esp32s3": "Heltec ESP32-S3 (Xtensa LX7)"}
BOARD_STYLE = {"esp32": dict(color=BLACK, marker="o", linestyle="-"), "esp32s3": dict(color=GREEN, marker="^", linestyle="--")}
CPU_MHZ = 240.0

def milhar(value, _pos=None):
    return f"{int(value):,}".replace(",", ".")

def style():
    plt.rcParams.update({
        "font.size": 9, "axes.titlesize": 9.5, "axes.labelsize": 9, "legend.fontsize": 8,
        "xtick.labelsize": 8, "ytick.labelsize": 8,
        "axes.spines.top": False, "axes.spines.right": False,
        "axes.grid": True, "grid.color": "#DDDDDD", "grid.linewidth": 0.6, "axes.axisbelow": True,
        "lines.linewidth": 1.6, "lines.markersize": 5, "legend.frameon": False,
        "savefig.dpi": 200, "pdf.fonttype": 42, "figure.facecolor": "white",
    })

def separate_small_ticks(ax):
    """Os rotulos 0 e 2 ficam colados; empurra um para cada lado do tick."""
    labels = ax.get_xticklabels()
    labels[0].set_ha("right")
    labels[1].set_ha("left")

def save(fig, outdir, name):
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(outdir, f"{name}.{ext}"))
    plt.close(fig)
    print("  ", name)

# ---------------------------------------------------------------------------
def fig_cycles(logs, outdir):
    """Ciclos por tamanho, cifragem em cima e decifragem embaixo, uma coluna por placa, eixo y comum."""
    fig, axes = plt.subplots(2, 2, figsize=(6.3, 5.2), sharex=True, sharey=True, layout="constrained")
    for col, d in enumerate(logs):
        for row, (op, ascon_idx, aes_key) in enumerate((("Cifragem", 0, "aesE"), ("Decifragem", 1, "aesD"))):
            ax = axes[row][col]
            ascon = [d["ascon"][s][ascon_idx] for s in SIZES]
            aes   = [d["cmp"][s][aes_key] for s in SIZES]
            ax.plot(SIZES, ascon, marker="o", color=BLUE, label="Ascon-128a (software)")
            ax.plot(SIZES, aes, marker="s", linestyle="--", color=VERMILLION, label="AES-128-GCM (mbedTLS)")
            if row == 0:
                ax.set_title(BOARD[d["alvo"]])
            ax.set_xticks(SIZES)
            ax.set_ylim(0, 24000)
            ax.yaxis.set_major_formatter(FuncFormatter(milhar))
            if row == 1:
                ax.set_xlabel("Payload (bytes)")
                separate_small_ticks(ax)
            if col == 0:
                ax.set_ylabel(f"{op}\nciclos de CPU")
            if col == 1:
                right = ax.secondary_yaxis("right", functions=(lambda c: c / CPU_MHZ, lambda u: u * CPU_MHZ))
                right.set_ylabel("Tempo a 240 MHz (µs)")
    axes[0][0].legend(loc="lower right")
    save(fig, outdir, "bench_ciclos_tamanho")

def fig_ratio(logs, outdir):
    """Razao AES-GCM / Ascon por tamanho, cifragem e decifragem lado a lado, uma linha por placa."""
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 3.0), sharey=True, layout="constrained")
    for ax, (op, key) in zip(axes, (("Cifragem", "ratioE"), ("Decifragem", "ratioD"))):
        ax.axhline(1.0, color=GRAY, linewidth=1, linestyle=":")
        ax.text(64, 1.0, " AES-GCM = Ascon", color=GRAY, fontsize=8, va="bottom", ha="right")
        for d in logs:
            ratio = [d["cmp"][s][key] for s in SIZES]
            ax.plot(SIZES, ratio, label=BOARD[d["alvo"]], **BOARD_STYLE[d["alvo"]])
            r23 = d["cmp"][23][key]
            ax.annotate(f"{r23:.2f}".replace(".", ","), (23, r23), xytext=(0, 6), textcoords="offset points",
                        ha="center", fontsize=8, color=BOARD_STYLE[d["alvo"]]["color"])
        ax.set_title(op)
        ax.set_xlabel("Payload (bytes)")
        ax.set_xticks(SIZES)
        separate_small_ticks(ax)
        ax.set_ylim(0, 4)
    axes[0].set_ylabel("Razão AES-GCM / Ascon")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside lower center", ncol=2)
    save(fig, outdir, "bench_razao_tamanho")

def fig_per_block(logs, outdir):
    """Custo marginal por bloco de 16 B: Ascon inteiro contra AES-GCM = CTR + GHASH."""
    fig, ax = plt.subplots(figsize=(6.3, 2.8), layout="constrained")
    positions, labels = [], []
    x = 0.0
    for d in logs:
        ascon = d["paths"]["Ascon-128a (software)"][3]
        ctr   = d["paths"]["AES-CTR (so cifra AES)"][3]
        gcm   = d["paths"]["AES-GCM (cifra + GHASH)"][3]
        ghash = gcm - ctr
        ax.bar(x, ascon, width=0.7, color=BLUE, label="Ascon-128a (cifra + autenticação)" if x == 0 else None)
        ax.text(x, ascon + 30, milhar(round(ascon)), ha="center", va="bottom", fontsize=8)
        ax.bar(x + 1, ctr, width=0.7, color=GREEN, label="AES-GCM: cifra AES (CTR)" if x == 0 else None)
        ax.bar(x + 1, ghash, width=0.7, bottom=ctr, color=VERMILLION, hatch="//", edgecolor="white", linewidth=0.5,
               label="AES-GCM: GHASH (software)" if x == 0 else None)
        ax.text(x + 1, gcm + 30, milhar(round(gcm)), ha="center", va="bottom", fontsize=8)
        if ctr > 300:
            ax.text(x + 1, ctr / 2, milhar(round(ctr)), ha="center", va="center", fontsize=7, color="white")
        else:
            ax.text(x + 1.4, ctr / 2, milhar(round(ctr)), ha="left", va="center", fontsize=7, color=GREEN)
        ax.text(x + 1, ctr + ghash / 2, milhar(round(ghash)), ha="center", va="center", fontsize=7, color="white")
        positions += [x, x + 1]
        labels += ["Ascon-128a", "AES-128-GCM"]
        ax.text(x + 0.5, -420, BOARD[d["alvo"]], ha="center", va="top", fontsize=8.5, clip_on=False)
        x += 2.6
    ax.set_xticks(positions)
    ax.set_xticklabels(labels)
    ax.set_ylabel("Ciclos por bloco de 16 B")
    ax.set_ylim(0, 2500)
    ax.yaxis.set_major_formatter(FuncFormatter(milhar))
    ax.legend(loc="upper right")
    ax.tick_params(axis="x", length=0)
    save(fig, outdir, "bench_decomposicao_bloco")

def fig_constant_time(logs, outdir):
    """Tempo constante: media menos piso por classe de entrada, dois tamanhos, uma placa por painel."""
    classes = ["rampa", "zeros", "uns (0xFF)", "alternado", "hash"]
    fig, axes = plt.subplots(1, 2, figsize=(6.3, 2.7), layout="constrained")
    for ax, d in zip(axes, logs):
        for size, marker, color in ((16, "o", BLUE), (64, "s", PURPLE)):
            rows = d["class_rows"][size]
            delta = [rows[c][1] - rows[c][0] for c in classes]
            ax.plot(range(len(classes)), delta, marker=marker, color=color, linestyle="none", label=f"{size} bytes")
            ax.plot(range(len(classes)), delta, color=color, linewidth=0.8, alpha=0.5)
        spread16 = max(d["class_rows"][16][c][1] for c in classes) - min(d["class_rows"][16][c][1] for c in classes)
        spread64 = max(d["class_rows"][64][c][1] for c in classes) - min(d["class_rows"][64][c][1] for c in classes)
        ax.set_title(BOARD[d["alvo"]])
        ax.set_xticks(range(len(classes)))
        ax.set_xticklabels(classes, rotation=20, ha="right")
        ax.set_ylim(0, max(6, 1.15 * max(max(d["class_rows"][s][c][1] - d["class_rows"][s][c][0] for c in classes) for s in (16, 64))))
        ax.text(0.03, 0.97, f"spread entre classes:\n16 B: {spread16:.2f} ciclos | 64 B: {spread64:.2f} ciclos".replace(".", ","),
                transform=ax.transAxes, fontsize=7.5, va="top")
    axes[0].set_ylabel("Média − piso (ciclos)")
    axes[0].legend(loc="center right")
    save(fig, outdir, "bench_tempo_constante")

if __name__ == "__main__":
    logs = [parse(p) for p in sys.argv[1:3]]
    outdir = sys.argv[3]
    os.makedirs(outdir, exist_ok=True)
    style()
    print("figuras em", outdir)
    fig_cycles(logs, outdir)
    fig_ratio(logs, outdir)
    fig_per_block(logs, outdir)
    fig_constant_time(logs, outdir)
