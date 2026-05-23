"""Generate src/data/interface_map.py from docs/INTERFACE-MAP.txt."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "docs" / "INTERFACE-MAP.txt"
TARGET = ROOT / "src" / "data" / "interface_map.py"

lines = SOURCE.read_text(encoding="utf-8").splitlines()

# Parse all entries after the device IP section (line 45+)
data: dict[str, dict[str, tuple[str, str | None]]] = {}
for line in lines[45:]:
    line_s = line.strip()
    if not line_s or line_s.startswith("#"):
        continue
    parts = [p.strip() for p in line_s.split("|")]
    if len(parts) >= 3:
        hostname = parts[0]
        iface = re.sub(r"\s+l2transport$", "", parts[1])
        desc = parts[2]
        bundle_raw = parts[3].strip() if len(parts) > 3 else ""
        bundle: str | None = None if bundle_raw in ("", "—", "-", "–") else bundle_raw

        if hostname not in data:
            data[hostname] = {}
        data[hostname][iface] = (desc, bundle)

# Generate Python source
out: list[str] = []
out.append('"""Interface-to-description mapping for all BSCCL network devices."""')
out.append("")
out.append("from __future__ import annotations")
out.append("")
out.append("import re")
out.append("from dataclasses import dataclass")
out.append("")
out.append("")
out.append("@dataclass(frozen=True)")
out.append("class InterfaceInfo:")
out.append('    """Description and parent bundle for a network interface."""')
out.append("")
out.append("    description: str")
out.append("    bundle: str | None")
out.append("")
out.append("")
out.append('_UNDERSCORE_RE = re.compile(r"(?<=[a-zA-Z0-9])_(?=\\d)")')
out.append("")
out.append("")
out.append("def _normalize_interface(name: str) -> str:")
out.append(
    '    """Normalize interface name: underscores between type and'
    ' slot numbers become slashes."""'
)
out.append('    return _UNDERSCORE_RE.sub("/", name)')
out.append("")
out.append("")
out.append("INTERFACE_MAP: dict[str, dict[str, InterfaceInfo]] = {")

for hostname in sorted(data.keys()):
    ifaces = data[hostname]
    out.append(f'    "{hostname}": {{')
    for iface_name in sorted(ifaces.keys()):
        desc, bundle = ifaces[iface_name]
        desc_escaped = desc.replace('"', '\\"')
        if bundle:
            bundle_escaped = bundle.replace('"', '\\"')
            line = (
                f'        "{iface_name}": InterfaceInfo'
                f'("{desc_escaped}", "{bundle_escaped}"),'
            )
            out.append(line)
        else:
            out.append(
                f'        "{iface_name}": InterfaceInfo("{desc_escaped}", None),'
            )
    out.append("    },")

out.append("}")
out.append("")
out.append("")
out.append(
    "def lookup_interface(hostname: str, interface: str) -> InterfaceInfo | None:"
)
out.append(
    '    """Resolve device hostname + interface name to description/bundle info.'
)
out.append("")
out.append("    Handles underscore-to-slash normalization (e.g. HundredGigE0_3_2_2).")
out.append('    Returns None for unknown hostname or interface."""')
out.append("    device_interfaces = INTERFACE_MAP.get(hostname)")
out.append("    if device_interfaces is None:")
out.append("        return None")
out.append("    normalized = _normalize_interface(interface)")
out.append("    return device_interfaces.get(normalized)")
out.append("")

content = "\n".join(out)
TARGET.write_text(content, encoding="utf-8")
total = sum(len(v) for v in data.values())
print(
    f"Generated {TARGET.name}: {len(content)} chars,"
    f" {len(data)} devices, {total} interfaces"
)
