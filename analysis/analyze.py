import csv
from collections import Counter
from dataclasses import dataclass
from datetime import date
from math import sqrt
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = ROOT / "data" / "mcp_security_records.csv"
OUT_DIR = ROOT / "generated"

NATURES = ["classic", "hybrid", "ai-native"]
NATURE_LABELS = {"classic": "Classic", "hybrid": "Hybrid", "ai-native": "AI-native"}
ORIGINS = ["implementation", "protocol-design", "integration-design", "supply-chain", "deployment"]
ORIGIN_LABELS = {
    "implementation": "Implementation",
    "protocol-design": "Protocol design",
    "integration-design": "Integration design",
    "supply-chain": "Supply chain",
    "deployment": "Deployment",
}
COMPONENTS = ["Server", "Host", "Protocol", "Ecosystem", "SDK", "Dev tooling"]
WEAKNESS_NATURE = {
    "command-injection": "classic",
    "path-traversal": "classic",
    "ssrf": "classic",
    "access-control": "classic",
    "isolation": "classic",
    "malicious-package": "classic",
    "integrity-check": "classic",
    "credential-exposure": "classic",
    "injection-via-server": "ai-native",
    "injection-via-content": "ai-native",
    "mixed": "hybrid",
}
MAIN_FAMILIES = ["command-injection", "path-traversal", "ssrf", "access-control"]


@dataclass(frozen=True)
class Record:
    record_id: str
    title: str
    identifier: str
    disclosed: date
    component: str
    nature: str
    origin: str
    weakness: str
    insecure_default: bool
    first_party: bool
    source: str

    @property
    def has_cve(self) -> bool:
        return self.identifier.startswith("CVE-")

    @property
    def quarter(self) -> str:
        return f"{self.disclosed.year} Q{(self.disclosed.month - 1) // 3 + 1}"


def load_records(path: Path) -> list[Record]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [
            Record(
                record_id=row["id"],
                title=row["title"],
                identifier=row["identifier"],
                disclosed=date.fromisoformat(row["disclosed"]),
                component=row["component"],
                nature=row["nature"],
                origin=row["origin"],
                weakness=row["weakness"],
                insecure_default=row["insecure_default"] == "yes",
                first_party=row["first_party"] == "yes",
                source=row["source"],
            )
            for row in csv.DictReader(handle)
        ]


def validate(records: list[Record]) -> None:
    for record in records:
        if record.nature not in NATURES:
            raise ValueError(f"{record.record_id}: unknown nature {record.nature}")
        if record.origin not in ORIGINS:
            raise ValueError(f"{record.record_id}: unknown origin {record.origin}")
        if record.component not in COMPONENTS:
            raise ValueError(f"{record.record_id}: unknown component {record.component}")
        if WEAKNESS_NATURE.get(record.weakness) != record.nature:
            raise ValueError(f"{record.record_id}: weakness {record.weakness} does not match nature {record.nature}")


def percent(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}" if whole else "0.0"


def wilson_interval(part: int, whole: int, z: float = 1.96) -> tuple[float, float]:
    share = part / whole
    denominator = 1 + z**2 / whole
    centre = (share + z**2 / (2 * whole)) / denominator
    margin = z * sqrt(share * (1 - share) / whole + z**2 / (4 * whole**2)) / denominator
    return 100 * (centre - margin), 100 * (centre + margin)


def macro(name: str, value: object) -> str:
    return f"\\newcommand{{\\{name}}}{{{value}}}"


def build_stats(records: list[Record]) -> str:
    total = len(records)
    natures = Counter(r.nature for r in records)
    cve_records = [r for r in records if r.has_cve]
    cve_natures = Counter(r.nature for r in cve_records)
    first_party = [r for r in records if r.first_party]
    defaults = [r for r in records if r.insecure_default]
    implementation_classic = sum(1 for r in records if r.nature == "classic" and r.origin == "implementation")
    vmp = sum(1 for r in records if r.source == "VMP")
    weaknesses = Counter(r.weakness for r in records)
    native_origins = Counter(r.origin for r in records if r.nature == "ai-native")
    servers = [r for r in records if r.component == "Server"]
    classic_low, classic_high = wilson_interval(natures["classic"], total)
    lines = [
        macro("nRecords", total),
        macro("nVmp", vmp),
        macro("nSupplementary", total - vmp),
        macro("nClassic", natures["classic"]),
        macro("pClassic", percent(natures["classic"], total)),
        macro("nHybrid", natures["hybrid"]),
        macro("pHybrid", percent(natures["hybrid"], total)),
        macro("nNative", natures["ai-native"]),
        macro("pNative", percent(natures["ai-native"], total)),
        macro("nCve", len(cve_records)),
        macro("pCve", percent(len(cve_records), total)),
        macro("nCveClassic", cve_natures["classic"]),
        macro("nCveHybrid", cve_natures["hybrid"]),
        macro("nCveNative", cve_natures["ai-native"]),
        macro("pClassicWithCve", percent(cve_natures["classic"], natures["classic"])),
        macro("nFirstParty", len(first_party)),
        macro("nFirstPartyClassic", sum(1 for r in first_party if r.nature == "classic")),
        macro("nInsecureDefault", len(defaults)),
        macro("pInsecureDefaultOfClassic", percent(sum(1 for r in defaults if r.nature == "classic"), natures["classic"])),
        macro("nImplClassic", implementation_classic),
        macro("pImplClassic", percent(implementation_classic, total)),
        macro("pClassicComma", percent(natures["classic"], total).replace(".", ",")),
        macro("pNativeComma", percent(natures["ai-native"], total).replace(".", ",")),
        macro("ciClassicLow", f"{classic_low:.1f}"),
        macro("ciClassicHigh", f"{classic_high:.1f}"),
        macro("nCommandInjection", weaknesses["command-injection"]),
        macro("nPathTraversal", weaknesses["path-traversal"]),
        macro("nSsrf", weaknesses["ssrf"]),
        macro("nAccessControl", weaknesses["access-control"]),
        macro("nMainFamilies", sum(weaknesses[w] for w in MAIN_FAMILIES)),
        macro("nMaliciousPackage", weaknesses["malicious-package"]),
        macro("nNativeViaServer", weaknesses["injection-via-server"]),
        macro("nNativeViaContent", weaknesses["injection-via-content"]),
        macro("nNativeProtocol", native_origins["protocol-design"]),
        macro("nNativeIntegration", native_origins["integration-design"]),
        macro("nIntegration", sum(1 for r in records if r.origin == "integration-design")),
        macro("nServer", len(servers)),
        macro("nServerCve", sum(1 for r in servers if r.has_cve)),
        macro("firstDisclosure", min(r.disclosed for r in records).strftime("%B %Y")),
        macro("lastDisclosure", max(r.disclosed for r in records).strftime("%B %Y")),
    ]
    return "\n".join(lines) + "\n"


def build_origin_table(records: list[Record]) -> str:
    rows: list[str] = []
    for origin in ORIGINS:
        subset = [r for r in records if r.origin == origin]
        counts = Counter(r.nature for r in subset)
        cells = " & ".join(str(counts[n]) for n in NATURES)
        rows.append(f"{ORIGIN_LABELS[origin]} & {cells} & {len(subset)} \\\\")
    totals = Counter(r.nature for r in records)
    rows.append("\\midrule")
    rows.append("Total & " + " & ".join(str(totals[n]) for n in NATURES) + f" & {len(records)} \\\\")
    rows.append("\\bottomrule")
    return "\n".join(rows) + "\n"


def build_component_table(records: list[Record]) -> str:
    rows: list[str] = []
    for component in COMPONENTS:
        subset = [r for r in records if r.component == component]
        counts = Counter(r.nature for r in subset)
        cve = sum(1 for r in subset if r.has_cve)
        cells = " & ".join(str(counts[n]) for n in NATURES)
        rows.append(f"{component} & {cells} & {len(subset)} & {cve} \\\\")
    rows.append("\\bottomrule")
    return "\n".join(rows) + "\n"


def build_quarter_plot(records: list[Record]) -> str:
    quarters = sorted({r.quarter for r in records})
    blocks: list[str] = [f"\\pgfplotsset{{quarteraxis/.style={{symbolic x coords={{{','.join(quarters)}}}}}}}"]
    blocks.append("\\newcommand{\\quarterPlots}{%")
    for nature in NATURES:
        counts = Counter(r.quarter for r in records if r.nature == nature)
        coordinates = " ".join(f"({q},{counts[q]})" for q in quarters)
        blocks.append(f"\\addplot coordinates {{{coordinates}}};")
        blocks.append(f"\\addlegendentry{{{NATURE_LABELS[nature]}}}")
    blocks.append("}")
    return "\n".join(blocks) + "\n"


def build_nature_plot(records: list[Record]) -> str:
    blocks: list[str] = []
    for nature in NATURES:
        subset = [r for r in records if r.nature == nature]
        with_cve = sum(1 for r in subset if r.has_cve)
        name = NATURE_LABELS[nature].replace("-", "")
        blocks.append(f"\\def\\cveWith{name}{{{with_cve}}}")
        blocks.append(f"\\def\\cveWithout{name}{{{len(subset) - with_cve}}}")
    return "\n".join(blocks) + "\n"


def build_appendix(records: list[Record]) -> str:
    rows: list[str] = []
    short_origin = {
        "implementation": "Impl.",
        "protocol-design": "Protocol",
        "integration-design": "Integr.",
        "supply-chain": "Supply",
        "deployment": "Deploy.",
    }
    for r in sorted(records, key=lambda item: item.disclosed):
        identifier = r.identifier.replace("_", "\\_") or "--"
        rows.append(
            f"{r.record_id} & {r.title} & {identifier} & {r.disclosed.strftime('%m/%Y')} & "
            f"{NATURE_LABELS[r.nature]} & {short_origin[r.origin]} \\\\"
        )
    return "\n".join(rows) + "\n"


def main() -> None:
    records = load_records(DATA_FILE)
    validate(records)
    OUT_DIR.mkdir(exist_ok=True)
    outputs = {
        "stats.tex": build_stats(records),
        "origin_table.tex": build_origin_table(records),
        "component_table.tex": build_component_table(records),
        "quarter_plot.tex": build_quarter_plot(records),
        "nature_plot.tex": build_nature_plot(records),
        "appendix_table.tex": build_appendix(records),
    }
    for name, content in outputs.items():
        (OUT_DIR / name).write_text(content, encoding="utf-8")
    print(build_stats(records))
    print(build_origin_table(records))
    print(build_component_table(records))
    print(build_quarter_plot(records))
    print(build_nature_plot(records))


if __name__ == "__main__":
    main()
