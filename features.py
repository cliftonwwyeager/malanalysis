import json
import math
import os
import re
import struct
from pathlib import Path


ANALYSIS_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "confidence",
        "risk_score",
        "executable_type",
        "platform",
        "malware_family",
        "malware_category",
        "summary",
        "technical_description",
        "evidence",
        "indicators",
        "recommended_actions",
        "report_markdown",
    ],
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["benign", "suspicious", "malware", "unknown"],
        },
        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "executable_type": {"type": "string"},
        "platform": {"type": "string"},
        "malware_family": {"type": "string"},
        "malware_category": {"type": "string"},
        "summary": {"type": "string"},
        "technical_description": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "indicators": {"type": "array", "items": {"type": "string"}},
        "recommended_actions": {"type": "array", "items": {"type": "string"}},
        "report_markdown": {"type": "string"},
    },
}

SYSTEM_PROMPT = """You are MGNN-8B, a defensive executable-analysis model.

Purpose:
- Detect, classify, describe, and report on submitted executable metadata.
- Work only from static metadata supplied by the user.
- Never claim dynamic behavior, execution, network contact, or malware family evidence unless it is directly supported by the metadata.
- Treat missing evidence as unknown.

Return exactly one JSON object and no Markdown fences. The object must contain:
- verdict: benign, suspicious, malware, or unknown
- confidence: number from 0.0 to 1.0
- risk_score: integer from 0 to 100
- executable_type
- platform
- malware_family, or unknown
- malware_category, or unknown
- summary
- technical_description
- evidence: array of concise observations
- indicators: array of hashes, strings, packer hints, or IOCs
- recommended_actions: array of defensive next steps
- report_markdown: incident-response-ready report"""

SUSPICIOUS_PATTERNS = {
    "credential_access": [
        "password",
        "credential",
        "lsass",
        "mimikatz",
    ],
    "process_injection": [
        "virtualalloc",
        "writeprocessmemory",
        "createremotethread",
        "ntmapviewofsection",
        "setwindowshookex",
    ],
    "execution": [
        "cmd.exe",
        "powershell",
        "wscript",
        "cscript",
        "rundll32",
        "regsvr32",
    ],
    "persistence": [
        "\\run\\",
        "currentversion\\run",
        "schtasks",
        "startup",
        "launchdaemon",
    ],
    "network": [
        "http://",
        "https://",
        "socket",
        "connect",
        "wininet",
        "urlmon",
    ],
    "anti_analysis": [
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "ollydbg",
        "wireshark",
        "sandbox",
        "vmware",
        "virtualbox",
    ],
}

PE_MACHINES = {
    0x014C: "x86",
    0x0200: "Intel Itanium",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

ELF_MACHINES = {
    0x03: "x86",
    0x3E: "x64",
    0x28: "ARM",
    0xB7: "ARM64",
    0xF3: "RISC-V",
}

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("Mach-O", "32-bit big-endian"),
    b"\xce\xfa\xed\xfe": ("Mach-O", "32-bit little-endian"),
    b"\xfe\xed\xfa\xcf": ("Mach-O", "64-bit big-endian"),
    b"\xcf\xfa\xed\xfe": ("Mach-O", "64-bit little-endian"),
    b"\xca\xfe\xba\xbe": ("Mach-O universal", "fat binary"),
    b"\xbe\xba\xfe\xca": ("Mach-O universal", "fat binary reverse"),
}


class AnalysisParseError(RuntimeError):
    pass


def _clamp(value, lower, upper):
    return max(lower, min(upper, value))


def _entropy_from_counts(counts, total):
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _entropy_bytes(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    return _entropy_from_counts(counts, len(data))


def _hash_entropy_and_sample(file_path, max_sample_bytes):
    import hashlib

    digest = hashlib.sha256()
    counts = [0] * 256
    total = 0
    sample = bytearray()
    with open(file_path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1
            if len(sample) < max_sample_bytes:
                remaining = max_sample_bytes - len(sample)
                sample.extend(chunk[:remaining])
    return digest.hexdigest(), _entropy_from_counts(counts, total), bytes(sample)


def _u16(data, offset, endian="<"):
    if offset + 2 > len(data):
        return None
    return struct.unpack_from(f"{endian}H", data, offset)[0]


def _u32(data, offset, endian="<"):
    if offset + 4 > len(data):
        return None
    return struct.unpack_from(f"{endian}I", data, offset)[0]


def _u64(data, offset, endian="<"):
    if offset + 8 > len(data):
        return None
    return struct.unpack_from(f"{endian}Q", data, offset)[0]


def _decode_ascii(raw):
    return raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore").strip()


def _extract_strings(sample, limit=80):
    strings = []
    seen = set()
    for match in re.finditer(rb"[ -~]{4,}", sample):
        text = match.group(0).decode("utf-8", errors="ignore").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        strings.append(text[:160])
        if len(strings) >= limit:
            break
    return strings


def _find_suspicious_strings(strings):
    findings = []
    for text in strings:
        lowered = text.lower()
        for category, patterns in SUSPICIOUS_PATTERNS.items():
            if any(pattern in lowered for pattern in patterns):
                findings.append({"category": category, "value": text[:160]})
                break
    return findings[:30]


def _parse_pe(sample):
    if len(sample) < 0x40 or sample[:2] != b"MZ":
        return None
    pe_offset = _u32(sample, 0x3C)
    if pe_offset is None or pe_offset + 24 > len(sample):
        return {
            "type": "PE",
            "valid_header": False,
            "reason": "Missing or truncated PE header",
        }
    if sample[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return {
            "type": "PE",
            "valid_header": False,
            "reason": "MZ header present but PE signature was not found",
        }

    coff = pe_offset + 4
    machine = _u16(sample, coff)
    section_count = _u16(sample, coff + 2) or 0
    timestamp = _u32(sample, coff + 4)
    optional_size = _u16(sample, coff + 16) or 0
    characteristics = _u16(sample, coff + 18) or 0
    optional = coff + 20
    optional_magic = _u16(sample, optional)
    entry_point = _u32(sample, optional + 16)
    subsystem = _u16(sample, optional + 68)
    dll_characteristics = _u16(sample, optional + 70)

    sections = []
    section_table = optional + optional_size
    for index in range(min(section_count, 32)):
        base = section_table + index * 40
        if base + 40 > len(sample):
            break
        raw_size = _u32(sample, base + 16) or 0
        raw_ptr = _u32(sample, base + 20) or 0
        raw = sample[raw_ptr : raw_ptr + raw_size] if raw_ptr < len(sample) else b""
        sections.append(
            {
                "name": _decode_ascii(sample[base : base + 8]),
                "virtual_size": _u32(sample, base + 8),
                "virtual_address": _u32(sample, base + 12),
                "raw_size": raw_size,
                "entropy": round(_entropy_bytes(raw), 3) if raw else None,
                "characteristics": hex(_u32(sample, base + 36) or 0),
            }
        )

    section_names = {section["name"].lower() for section in sections}
    packer_hints = []
    for packed_name in ("upx0", "upx1", ".aspack", ".petite", ".themida"):
        if packed_name in section_names:
            packer_hints.append(f"Packed section name: {packed_name}")
    for section in sections:
        entropy = section.get("entropy")
        if entropy is not None and entropy >= 7.2:
            packer_hints.append(
                f"High entropy section {section.get('name') or '<unnamed>'}: {entropy}"
            )

    return {
        "type": "PE",
        "valid_header": True,
        "machine": PE_MACHINES.get(machine, f"unknown:{machine}"),
        "section_count": section_count,
        "timestamp": timestamp,
        "characteristics": hex(characteristics),
        "optional_magic": hex(optional_magic) if optional_magic is not None else None,
        "entry_point_rva": entry_point,
        "subsystem": subsystem,
        "dll_characteristics": hex(dll_characteristics)
        if dll_characteristics is not None
        else None,
        "sections": sections,
        "packer_hints": packer_hints[:12],
    }


def _parse_elf(sample):
    if len(sample) < 20 or sample[:4] != b"\x7fELF":
        return None
    elf_class = sample[4]
    endian_marker = sample[5]
    endian = "<" if endian_marker == 1 else ">" if endian_marker == 2 else "<"
    bits = "32-bit" if elf_class == 1 else "64-bit" if elf_class == 2 else "unknown"
    entry = _u32(sample, 24, endian) if elf_class == 1 else _u64(sample, 24, endian)
    machine = _u16(sample, 18, endian)
    return {
        "type": "ELF",
        "valid_header": True,
        "bits": bits,
        "endianness": "little" if endian == "<" else "big",
        "object_type": _u16(sample, 16, endian),
        "machine": ELF_MACHINES.get(machine, f"unknown:{machine}"),
        "entry_point": entry,
    }


def _parse_macho(sample):
    if len(sample) < 4:
        return None
    magic = sample[:4]
    if magic not in MACHO_MAGICS:
        return None
    file_type, detail = MACHO_MAGICS[magic]
    return {
        "type": file_type,
        "valid_header": True,
        "detail": detail,
        "magic": magic.hex(),
    }


def _detect_format(sample):
    for parser in (_parse_pe, _parse_elf, _parse_macho):
        parsed = parser(sample)
        if parsed:
            return parsed
    if sample.startswith(b"#!"):
        first_line = sample.split(b"\n", 1)[0].decode("utf-8", errors="ignore")
        return {"type": "script", "valid_header": True, "interpreter": first_line}
    return {"type": "unknown", "valid_header": False}


def extract_executable_features(file_path, max_sample_bytes=None):
    path = Path(file_path)
    if max_sample_bytes is None:
        max_sample_bytes = int(os.getenv("MGNN_MAX_FEATURE_BYTES", str(1024 * 1024)))
    sha256, entropy, sample = _hash_entropy_and_sample(path, max_sample_bytes)
    strings = _extract_strings(sample)
    detected_format = _detect_format(sample)
    suspicious_strings = _find_suspicious_strings(strings)
    high_entropy = entropy >= 7.2
    string_density = round(len(strings) / max(1, len(sample) / 4096), 3)

    return {
        "file_name": path.name,
        "size_bytes": path.stat().st_size,
        "sha256": sha256,
        "sampled_bytes": len(sample),
        "overall_entropy": round(entropy, 3),
        "high_entropy": high_entropy,
        "string_count_sample": len(strings),
        "string_density_per_4kb": string_density,
        "format": detected_format,
        "suspicious_strings": suspicious_strings,
        "strings_sample": strings[:50],
    }


def build_analysis_prompt(features):
    feature_json = json.dumps(features, indent=2, sort_keys=True)
    return (
        "Analyze this executable metadata. Return one JSON object matching the "
        "MGNN schema from your system instructions. Do not include Markdown fences "
        "or explanatory text outside the JSON object.\n\n"
        f"{feature_json}\n"
    )


def extract_json_object(text):
    cleaned = re.sub(r"\x1b\[[0-9;]*m", "", text).strip()
    cleaned = re.sub(r"^```(?:json)?|```$", "", cleaned, flags=re.IGNORECASE).strip()
    start = cleaned.find("{")
    if start < 0:
        raise AnalysisParseError("Model output did not contain a JSON object")

    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(cleaned)):
        char = cleaned[index]
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return cleaned[start : index + 1]
    raise AnalysisParseError("Model output contained incomplete JSON")


def _as_string_list(value, limit=20):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()][:limit]
    text = str(value).strip()
    return [text] if text else []


def _normalize_verdict(value):
    text = str(value or "unknown").strip().lower()
    if "mal" in text or "trojan" in text or "ransom" in text:
        return "malware"
    if "susp" in text or "risk" in text or "possibly" in text:
        return "suspicious"
    if "benign" in text or "clean" in text:
        return "benign"
    return "unknown"


def _normalize_confidence(value):
    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0
    if confidence > 1 and confidence <= 100:
        confidence /= 100.0
    return round(_clamp(confidence, 0.0, 1.0), 4)


def _normalize_risk_score(value, verdict, confidence):
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        score = {
            "malware": 85,
            "suspicious": 60,
            "benign": 15,
            "unknown": 40,
        }[verdict]
        if confidence:
            score = int(round(score * confidence))
    return int(_clamp(score, 0, 100))


def _default_report(analysis, features):
    return (
        "## MGNN Executable Analysis Report\n\n"
        f"**File:** {features['file_name']}\n\n"
        f"**SHA256:** `{features['sha256']}`\n\n"
        f"**Verdict:** {analysis['verdict']} "
        f"(confidence {analysis['confidence']:.2f}, risk {analysis['risk_score']}/100)\n\n"
        f"**Summary:** {analysis['summary']}\n\n"
        "### Evidence\n"
        + "\n".join(f"- {item}" for item in analysis["evidence"])
        + "\n\n### Recommended Actions\n"
        + "\n".join(f"- {item}" for item in analysis["recommended_actions"])
    )


def normalize_analysis(raw, features, framework="ollama", model_name="mgnn:8b"):
    verdict = _normalize_verdict(raw.get("verdict"))
    confidence = _normalize_confidence(raw.get("confidence"))
    risk_score = _normalize_risk_score(raw.get("risk_score"), verdict, confidence)
    predicted_class = 1 if verdict in {"malware", "suspicious"} else 0 if verdict == "benign" else -1

    analysis = {
        "schema_version": "mgnn.llm.analysis.v1",
        "analysis_status": "complete",
        "model_profile": "mgnn-executable-analyst-8b",
        "framework": framework,
        "model": model_name,
        "file_name": features["file_name"],
        "sha256": features["sha256"],
        "file_size": features["size_bytes"],
        "file_type": features["format"].get("type", "unknown"),
        "predicted_class": predicted_class,
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk_score,
        "classification": {
            "executable_type": str(raw.get("executable_type") or features["format"].get("type") or "unknown"),
            "platform": str(raw.get("platform") or "unknown"),
            "malware_family": str(raw.get("malware_family") or "unknown"),
            "malware_category": str(raw.get("malware_category") or "unknown"),
        },
        "summary": str(raw.get("summary") or "No summary returned by model."),
        "technical_description": str(raw.get("technical_description") or ""),
        "evidence": _as_string_list(raw.get("evidence")),
        "indicators": _as_string_list(raw.get("indicators")),
        "recommended_actions": _as_string_list(raw.get("recommended_actions")),
        "file_metadata": {
            "overall_entropy": features["overall_entropy"],
            "sampled_bytes": features["sampled_bytes"],
            "string_count_sample": features["string_count_sample"],
            "string_density_per_4kb": features["string_density_per_4kb"],
            "format": features["format"],
            "suspicious_strings": features["suspicious_strings"],
        },
    }
    if not analysis["evidence"]:
        analysis["evidence"] = [
            f"Format: {analysis['file_type']}",
            f"Entropy: {features['overall_entropy']}",
            f"Suspicious string hits: {len(features['suspicious_strings'])}",
        ]
    if not analysis["recommended_actions"]:
        analysis["recommended_actions"] = [
            "Correlate the hash with threat intelligence sources.",
            "Analyze the file in an isolated malware-analysis sandbox before execution.",
        ]
    report = str(raw.get("report_markdown") or "").strip()
    analysis["report_markdown"] = report or _default_report(analysis, features)
    return analysis


def heuristic_analysis(features, reason="metadata-only analysis"):
    reason = str(reason).rstrip(".")
    risk = 10
    evidence = [
        f"Format identified as {features['format'].get('type', 'unknown')}",
        f"Overall entropy is {features['overall_entropy']}",
    ]

    if features["format"].get("type") in {"PE", "ELF", "Mach-O", "Mach-O universal"}:
        risk += 15
    if features["high_entropy"]:
        risk += 25
        evidence.append("High overall entropy can indicate packing or encryption")
    packer_hints = features["format"].get("packer_hints", [])
    if packer_hints:
        risk += 20
        evidence.extend(packer_hints[:4])
    suspicious_strings = features["suspicious_strings"]
    if suspicious_strings:
        risk += min(30, len(suspicious_strings) * 5)
        evidence.extend(
            f"{item['category']}: {item['value']}" for item in suspicious_strings[:6]
        )

    risk = int(_clamp(risk, 0, 100))
    verdict = "malware" if risk >= 75 else "suspicious" if risk >= 40 else "benign"
    confidence = 0.35 if verdict == "benign" else 0.45 if verdict == "suspicious" else 0.55
    raw = {
        "verdict": verdict,
        "confidence": confidence,
        "risk_score": risk,
        "executable_type": features["format"].get("type", "unknown"),
        "platform": "unknown",
        "malware_family": "unknown",
        "malware_category": "unknown",
        "summary": (
            f"{reason}. Static metadata produced a {verdict} verdict with risk "
            f"{risk}/100. Use the imported MGNN Ollama model for calibrated results."
        ),
        "technical_description": "Heuristic fallback based on file header, entropy, section hints, and sampled strings.",
        "evidence": evidence,
        "indicators": [features["sha256"]],
        "recommended_actions": [
            "Run the extracted metadata through the imported MGNN Ollama model.",
            "Submit the file to an isolated sandbox for behavioral validation.",
            "Correlate SHA256 and notable strings against SIEM and threat-intel data.",
        ],
        "report_markdown": "",
    }
    analysis = normalize_analysis(raw, features, framework="metadata", model_name="heuristic-fallback")
    analysis["analysis_status"] = "fallback"
    return analysis


def parse_model_response(text, features, model_name="mgnn:8b"):
    try:
        raw = json.loads(extract_json_object(text))
    except json.JSONDecodeError as exc:
        raise AnalysisParseError(f"Failed to parse model JSON: {exc}") from exc
    return normalize_analysis(raw, features, framework="ollama", model_name=model_name)
