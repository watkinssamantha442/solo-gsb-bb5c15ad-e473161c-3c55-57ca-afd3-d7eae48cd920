"""DKIM-Signature 的 h= 头字段覆盖审计（RFC 6376），复用邮件头折行解析。

审计口径（只看字段覆盖，不验证签名真伪）：
- 复用 :func:`mailtrace.parsing.parser.parse_header_blocks` 的折行展开，
  逐条收集 ``DKIM-Signature`` 字段（字段名大小写不敏感）。
- 每条签名独立解析其 ``h=`` 标签：标签按分号切分，``h`` 的值是冒号
  分隔的字段名列表，逐项保留（含重复项，不能按集合合并）。
- 按 ``h=`` 列表顺序，**从头部底部向上**（自后向前）为每个同名项
  匹配该条签名**尚未使用**的实际字段；已被前序 h 项消费的字段不会
  再匹配给后续同名项——这正是 RFC 6376 对重复字段名（如多个
  Received）的多重签名方式。
- 匹配池不包含本条 DKIM-Signature 自身（其 b= 尚在生成中），但
  包含位于其上方的其它（嵌套）DKIM-Signature 字段。
- 缺失 ``h=`` 标签或 ``h=`` 为空的签名标为异常，不进行匹配；
  完全没有 DKIM-Signature 字段时返回 ``status="none"``。
- 审计结果只表示 h= 列表对实际字段的覆盖情况，不宣称 DKIM 签名
  有效或通过验证（不检查 b=、d=、密钥或规范化值）。
"""

from __future__ import annotations

from mailtrace.parsing.parser import HeaderBlock, parse_header_blocks

DKIM_SIGNATURE = "dkim-signature"

# 重点核查的实际字段：即使未被某条签名的 h= 覆盖也要列出其实际副本
TARGET_FIELDS = ("from", "subject", "to", "date")
TARGET_DISPLAY = ("From", "Subject", "To", "Date")

STATUS_AUDITED = "audited"
STATUS_NONE = "none"

_STATUS_LABELS = {
    STATUS_AUDITED: "已完成 h= 覆盖审计",
    STATUS_NONE: "无 DKIM 签名",
}

# rel 取值：匹配/未覆盖字段相对于该条 DKIM-Signature 的位置
REL_ABOVE = "above"      # 在 DKIM-Signature 上方（先于签名字段出现）
REL_BELOW = "below"      # 在 DKIM-Signature 下方（签名之后追加）

REL_LABELS = {
    REL_ABOVE: "签名上方",
    REL_BELOW: "签名下方",
}


def _parse_tags(value: str) -> tuple[dict[str, str], set[str]]:
    """把分号分隔的 tag=value 列表解析为字典，返回 (标签字典, 重复标签名)。

    标签名统一小写；不带 ``=`` 的片段跳过；同名标签重复时保留首次
    出现的值并把标签名计入重复集合。
    """
    tags: dict[str, str] = {}
    duplicates: set[str] = set()
    for part in value.split(";"):
        if "=" not in part:
            continue
        name, _, val = part.partition("=")
        name = name.strip().lower()
        if not name:
            continue
        if name in tags:
            duplicates.add(name)
        else:
            tags[name] = val.strip()
    return tags, duplicates


def _parse_h_list(tags: dict[str, str]) -> list[str]:
    """把 h= 标签值拆为字段名列表（保留重复项与原始大小写、去除空白）。"""
    raw = tags.get("h", "")
    return [item.strip() for item in raw.split(":") if item.strip()]


def _anomaly(code: str, message: str) -> dict:
    return {"code": code, "message": message}


def _block_value_preview(block: HeaderBlock, limit: int = 160) -> str:
    value = block.value
    return value if len(value) <= limit else value[:limit] + "…"


def _match_h_entries(
    entries: list[str],
    all_blocks: list[HeaderBlock],
    sig_order: int,
) -> list[dict]:
    """按 h= 列表顺序，自头部底部向上逐条匹配尚未使用的实际字段。

    匹配池为除本条 DKIM-Signature 自身外的全部实际字段（含其上方的
    嵌套 DKIM-Signature）；每个实际字段最多消费一次，重复字段名
    因此按列表位置一一对应而不是按集合合并。
    """
    used: set[int] = set()
    results: list[dict] = []
    for index, entry in enumerate(entries):
        wanted = entry.lower()
        match: HeaderBlock | None = None
        # 从头部底部向上扫描（order 越大越靠近底部）
        for block in reversed(all_blocks):
            if block.order in used:
                continue
            if block.order == sig_order:
                # 本条 DKIM-Signature 自身不参与匹配
                continue
            if block.name.lower() == wanted:
                match = block
                break
        if match is None:
            results.append(
                {
                    "index": index,
                    "name": entry,
                    "matched": False,
                    "position": None,
                    "relative": None,
                    "relative_label": None,
                    "value": None,
                }
            )
            continue
        used.add(match.order)
        rel = REL_ABOVE if match.order < sig_order else REL_BELOW
        results.append(
            {
                "index": index,
                "name": entry,
                "matched": True,
                "position": match.order + 1,  # 位置自 1 起，按头部自上而下
                "relative": rel,
                "relative_label": REL_LABELS[rel],
                "value": _block_value_preview(match),
            }
        )
    return results


def _uncovered_targets(
    matched: list[dict],
    all_blocks: list[HeaderBlock],
    sig_order: int,
) -> list[dict]:
    """列出 From/Subject/To/Date 中未被该签名覆盖的实际副本（逐条不合并）。"""
    used_positions = {
        item["position"] for item in matched if item["matched"]
    }
    groups: list[dict] = []
    for lower_name, display in zip(TARGET_FIELDS, TARGET_DISPLAY):
        copies = [b for b in all_blocks if b.name.lower() == lower_name]
        uncovered = [b for b in copies if (b.order + 1) not in used_positions]
        if not uncovered:
            continue
        groups.append(
            {
                "field": display,
                "total_count": len(copies),
                "uncovered_count": len(uncovered),
                "copies": [
                    {
                        "position": b.order + 1,
                        "relative": (
                            REL_ABOVE if b.order < sig_order else REL_BELOW
                        ),
                        "relative_label": (
                            REL_LABELS[REL_ABOVE]
                            if b.order < sig_order
                            else REL_LABELS[REL_BELOW]
                        ),
                        "value": _block_value_preview(b),
                    }
                    for b in uncovered
                ],
            }
        )
    return groups


def _audit_signature(
    block: HeaderBlock, all_blocks: list[HeaderBlock]
) -> dict:
    tags, duplicate_tags = _parse_tags(block.value)
    anomalies: list[dict] = []

    if "h" not in tags:
        anomalies.append(
            _anomaly(
                "missing_h",
                "DKIM-Signature 缺少 h= 标签，无法确定被签名的头字段列表",
            )
        )
    if "h" in duplicate_tags:
        anomalies.append(
            _anomaly(
                "duplicate_h",
                "DKIM-Signature 的 h= 标签重复出现，h= 标签至多允许一个",
            )
        )

    entries = _parse_h_list(tags) if "h" in tags else []
    if "h" in tags and not entries:
        anomalies.append(
            _anomaly(
                "empty_h",
                "DKIM-Signature 的 h= 标签为空，没有任何头字段被该签名覆盖",
            )
        )

    if anomalies:
        # 异常签名不执行匹配，避免对缺失/空 h= 给出误导性覆盖结论
        matches = _match_h_entries([], all_blocks, block.order)
    else:
        matches = _match_h_entries(entries, all_blocks, block.order)

    unmatched = [item for item in matches if not item["matched"]]
    uncovered = _uncovered_targets(matches, all_blocks, block.order)

    domain = tags.get("d")
    selector = tags.get("s")

    return {
        "position": block.order + 1,
        "domain": domain,
        "selector": selector,
        "h_raw": tags.get("h"),
        "h_entries": entries,
        "h_count": len(entries),
        "anomalies": anomalies,
        "matches": matches,
        "matched_count": len(matches) - len(unmatched),
        "unmatched_entries": unmatched,
        "uncovered_targets": uncovered,
        "target_uncovered_count": sum(
            g["uncovered_count"] for g in uncovered
        ),
        "raw": block.raw,
    }


def analyze_dkim_coverage(raw_headers: str) -> dict:
    """审计邮件原始头部中每条 DKIM-Signature 的 h= 头字段覆盖情况。

    返回页面与 ``POST /api/dkim/coverage`` 共用的结构化结果；完全没有
    DKIM-Signature 字段时 ``status`` 为 ``"none"``。结果仅表示字段覆盖，
    不表示签名真伪或验证结论。
    """
    blocks = parse_header_blocks(raw_headers)
    sig_blocks = [b for b in blocks if b.name.lower() == DKIM_SIGNATURE]

    if not sig_blocks:
        return {
            "status": STATUS_NONE,
            "status_label": _STATUS_LABELS[STATUS_NONE],
            "signature_count": 0,
            "anomaly_count": 0,
            "signatures": [],
            "note": "未检测到 DKIM-Signature 字段：无 DKIM 签名可审计。",
        }

    signatures = [_audit_signature(b, blocks) for b in sig_blocks]
    anomaly_count = sum(len(s["anomalies"]) for s in signatures)

    return {
        "status": STATUS_AUDITED,
        "status_label": _STATUS_LABELS[STATUS_AUDITED],
        "signature_count": len(signatures),
        "anomaly_count": anomaly_count,
        "signatures": signatures,
        "note": "审计结果仅表示 h= 列表对实际头字段的覆盖情况，"
        "不验证 b= 签名、域名与密钥，不宣称 DKIM 签名真伪或验证是否通过。",
    }
