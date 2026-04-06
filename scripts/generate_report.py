#!/usr/bin/env python3
"""
故障分析报告生成脚本
接收结构化 JSON 数据，渲染 Markdown 报告
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

# 将 scripts 目录加入路径，以便导入 schema
sys.path.insert(0, str(Path(__file__).parent))

from schema import (
    AnalysisResult,
    BasicInfo,
    Source,
    TimelineEvent,
    TriggerAnalysis,
    RootCauseAnalysis,
    Recommendation,
    Priority,
    Category,
    Severity,
)


def _priority_from_str(value: str) -> Priority:
    """字符串转 Priority 枚举，非法值默认 P2"""
    mapping = {"P0": Priority.P0, "P1": Priority.P1, "P2": Priority.P2}
    return mapping.get(value.upper(), Priority.P2)


def _category_from_str(value: str) -> Category:
    """字符串转 Category 枚举"""
    if value.lower() in ("management", "管理"):
        return Category.MANAGEMENT
    return Category.TECHNICAL


def _severity_from_str(value: str) -> Severity:
    """字符串转 Severity 枚举"""
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(value.lower(), Severity.UNKNOWN)


def _ensure_list(val) -> list:
    """统一转 list，避免 null/None"""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]


def dict_to_analysis_result(data: dict) -> AnalysisResult:
    """
    将 AI 输出的结构化 JSON dict 转换为 AnalysisResult 对象
    """
    basic_dict = data.get("basic_info", {}) or {}
    timeline_list = _ensure_list(data.get("timeline"))
    rec_list = _ensure_list(data.get("recommendations"))

    # §2 BasicInfo
    basic = BasicInfo(
        incident_name=basic_dict.get("incident_name", ""),
        incident_id=basic_dict.get("incident_id"),
        start_time=basic_dict.get("start_time"),
        end_time=basic_dict.get("end_time"),
        duration=basic_dict.get("duration"),
        impact_scope=basic_dict.get("impact_scope", ""),
        severity=_severity_from_str(basic_dict.get("severity", "unknown")),
        status=basic_dict.get("status", ""),
        cvss_score=_float_or_none(basic_dict.get("cvss_score")),
        cvss_severity=basic_dict.get("cvss_severity"),
        cvss_vector=basic_dict.get("cvss_vector"),
        cwe_id=basic_dict.get("cwe_id"),
        cwe_name=basic_dict.get("cwe_name"),
        vendors=_ensure_list(basic_dict.get("vendors")),
        affected_products=_ensure_list(basic_dict.get("affected_products")),
    )

    # §3 Sources
    sources = [
        Source(
            url=s.get("url", ""),
            source_type=s.get("source_type", ""),
            title=s.get("title"),
            collected_via=s.get("collected_via", ""),
        )
        for s in _ensure_list(data.get("sources"))
    ]

    # §5 Timeline
    timeline = [
        TimelineEvent(
            timestamp=t.get("timestamp", ""),
            event=t.get("event", ""),
            impact=t.get("impact", ""),
            response_action=t.get("response_action", ""),
        )
        for t in timeline_list
    ]

    # §6 Triggers
    trig_dict = data.get("triggers", {}) or {}
    triggers = TriggerAnalysis(
        trigger_condition=trig_dict.get("trigger_condition", ""),
        trigger_path=trig_dict.get("trigger_path", ""),
        cascade_path=_ensure_list(trig_dict.get("cascade_path")),
        amplification_factors=_ensure_list(trig_dict.get("amplification_factors")),
    )

    # §7 Root Causes
    rc_dict = data.get("root_causes", {}) or {}
    root_causes = RootCauseAnalysis(
        direct_cause=rc_dict.get("direct_cause", ""),
        root_cause=rc_dict.get("root_cause", ""),
        human_factors=_ensure_list(rc_dict.get("human_factors")),
        organizational_factors=_ensure_list(rc_dict.get("organizational_factors")),
    )

    # §8 Recommendations
    recommendations = [
        Recommendation(
            priority=_priority_from_str(r.get("priority", "P2")),
            category=_category_from_str(r.get("category", "technical")),
            description=r.get("description", ""),
            expected_effect=r.get("expected_effect", ""),
            difficulty=r.get("difficulty", ""),
        )
        for r in rec_list
    ]

    # §9 References
    references = [
        Source(
            url=r.get("url", ""),
            source_type=r.get("source_type", ""),
            title=r.get("title"),
            collected_via=r.get("collected_via", ""),
        )
        for r in _ensure_list(data.get("references"))
    ]

    return AnalysisResult(
        executive_summary=data.get("executive_summary", ""),
        basic_info=basic,
        sources=sources,
        official_summary=data.get("official_summary", ""),
        timeline=timeline,
        triggers=triggers,
        root_causes=root_causes,
        recommendations=recommendations,
        references=references,
        mode=data.get("mode", "general"),
        cve_id=data.get("cve_id"),
    )


def _float_or_none(val) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def generate_report_from_dict(data: dict) -> str:
    """
    接收结构化 JSON dict，渲染 Markdown 报告并返回字符串
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError:
        raise ImportError(
            "缺少 jinja2 依赖，请运行: pip install jinja2\n"
            "或确保 requirements.txt 包含 jinja2>=3.1.0"
        )

    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    # 注册自定义 filter
    env.filters["priority_value"] = lambda r: r.priority.value

    result = dict_to_analysis_result(data)
    template = env.get_template("report.md.j2")
    return template.render(
        **{
            "basic_info": result.basic_info,
            "executive_summary": result.executive_summary,
            "sources": result.sources,
            "official_summary": result.official_summary,
            "timeline": result.timeline,
            "triggers": result.triggers,
            "root_causes": result.root_causes,
            "recommendations": result.recommendations,
            "references": result.references,
            "mode": result.mode,
            "cve_id": result.cve_id,
            "generated_date": datetime.now().strftime("%Y-%m-%d"),
        }
    )


def generate_report(json_path: str, output_path: str | None = None) -> str:
    """
    主入口：从 JSON 文件读取数据，生成报告并写入文件

    Args:
        json_path:  结构化分析结果的 JSON 文件路径
        output_path: 输出 Markdown 路径（默认与 JSON 同名，扩展名改为 .md）
    """
    with open(json_path, encoding="utf-8") as f:
        data = json.load(f)

    report_md = generate_report_from_dict(data)

    if output_path is None:
        output_path = str(Path(json_path).with_suffix(".md"))

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_md)

    print(f"报告已生成: {output_path}")
    return report_md


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print("用法: python generate_report.py <analysis_result.json> [output.md]")
        print("示例: python generate_report.py analysis_result.json")
        print("       python generate_report.py analysis_result.json report.md")
        sys.exit(1)

    json_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        report = generate_report(json_path, output_path)
        print(report)
    except FileNotFoundError:
        print(f"错误: 文件不存在 — {json_path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误: JSON 解析失败 — {e}", file=sys.stderr)
        sys.exit(1)
    except ImportError as e:
        print(f"错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
