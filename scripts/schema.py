#!/usr/bin/env python3
"""
故障分析结果数据模型
定义 Steps 2-5 结构化输出的 Schema，供 report generator 使用
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Priority(Enum):
    P0 = "P0"   # 紧急，立即处理
    P1 = "P1"   # 重要，短期处理
    P2 = "P2"   # 长期改进


class Category(Enum):
    TECHNICAL = "technical"    # 技术层面
    MANAGEMENT = "management"  # 管理层面


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class BasicInfo:
    """§2 故障基本信息"""
    incident_name: str = ""
    incident_id: Optional[str] = None        # CVE编号或事件编号
    start_time: Optional[str] = None          # 故障开始时间
    end_time: Optional[str] = None          # 故障恢复时间
    duration: Optional[str] = None           # 持续时长
    impact_scope: str = ""                   # 影响范围
    severity: Severity = Severity.UNKNOWN     # 严重等级
    status: str = ""                         # 当前状态

    # CVE 模式特有字段
    cvss_score: Optional[float] = None
    cvss_severity: Optional[str] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    cwe_name: Optional[str] = None
    vendors: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)


@dataclass
class Source:
    """§3 信息来源 + §9 参考资料"""
    url: str
    source_type: str = ""    # e.g. "Vendor Advisory", "NVD", "官方博客"
    title: Optional[str] = None
    collected_via: str = ""  # 数据获取方式: "NVD API" / "网页抓取" / "搜索引擎"


@dataclass
class TimelineEvent:
    """§5 时间线分析 — 单个事件"""
    timestamp: str           # 时间点/时间段
    event: str               # 事件描述
    impact: str = ""         # 影响
    response_action: str = "" # 响应行动


@dataclass
class TriggerAnalysis:
    """§6 导火索与故障链分析"""
    trigger_condition: str = ""   # 触发条件
    trigger_path: str = ""        # 触发路径（谁/什么/何时/如何）
    cascade_path: list[str] = field(default_factory=list)  # 级联故障路径列表
    amplification_factors: list[str] = field(default_factory=list)  # 放大因子列表


@dataclass
class RootCauseAnalysis:
    """§7 根本原因分析"""
    direct_cause: str = ""                       # 直接原因
    root_cause: str = ""                         # 根本原因
    human_factors: list[str] = field(default_factory=list)   # 人员因素
    organizational_factors: list[str] = field(default_factory=list)  # 组织架构因素


@dataclass
class Recommendation:
    """§8 改进建议 — 单条建议"""
    priority: Priority = Priority.P2
    category: Category = Category.TECHNICAL
    description: str = ""
    expected_effect: str = ""
    difficulty: str = ""   # "低" / "中" / "高"


@dataclass
class AnalysisResult:
    """
    故障分析完整结果
    对应报告 §1-§9 各章节的数据容器
    """
    # §1 执行摘要（仍由 AI 生成摘要文本）
    executive_summary: str = ""

    # §2 故障基本信息
    basic_info: BasicInfo = field(default_factory=BasicInfo)

    # §3 信息来源说明
    sources: list[Source] = field(default_factory=list)

    # §4 官方故障报告概要（仍由 AI 生成摘要文本）
    official_summary: str = ""

    # §5 时间线分析
    timeline: list[TimelineEvent] = field(default_factory=list)

    # §6 导火索与故障链分析
    triggers: TriggerAnalysis = field(default_factory=TriggerAnalysis)

    # §7 根本原因分析
    root_causes: RootCauseAnalysis = field(default_factory=RootCauseAnalysis)

    # §8 改进建议
    recommendations: list[Recommendation] = field(default_factory=list)

    # §9 参考资料
    references: list[Source] = field(default_factory=list)

    # 元数据
    mode: str = ""   # "cve" 或 "general"
    cve_id: Optional[str] = None
