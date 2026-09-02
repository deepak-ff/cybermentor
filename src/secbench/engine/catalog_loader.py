"""Load CIS benchmark catalogs from YAML files into Benchmark objects."""

from __future__ import annotations

import logging
from importlib import resources
from pathlib import Path
from typing import Iterable

import yaml

from .errors import CatalogError
from .models import Benchmark, Control, Section

log = logging.getLogger(__name__)


# (package_name, catalog_filename) for every supported benchmark.
BENCHMARK_PACKAGES: list[tuple[str, str]] = [
    ("secbench.benchmarks.azure_foundations_6_0_0", "catalog.yaml"),
    ("secbench.benchmarks.azure_compute_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.azure_database_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.azure_storage_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.m365_foundations_6_0_1", "catalog.yaml"),
    ("secbench.benchmarks.macos_tahoe_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.rhel_10_1_0_1", "catalog.yaml"),
    ("secbench.benchmarks.rhel_9_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.rhel_9_stig_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.rhel_8_4_0_0", "catalog.yaml"),
    ("secbench.benchmarks.rhel_8_stig_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.defender_av_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.windows_11_enterprise_5_0_1", "catalog.yaml"),
    ("secbench.benchmarks.windows_11_standalone_5_0_0", "catalog.yaml"),
    ("secbench.benchmarks.azure_compute_win_server_2022_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.azure_compute_win_server_2019_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2025_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2025_standalone_1_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2022_5_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2022_standalone_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2022_stig_2_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2019_4_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2019_standalone_3_0_0", "catalog.yaml"),
    ("secbench.benchmarks.win_server_2019_stig_3_0_0", "catalog.yaml"),
]


def _load_yaml_text(text: str, source: str) -> dict:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CatalogError(f"Invalid YAML in {source}: {exc}") from exc
    if not isinstance(data, dict):
        raise CatalogError(f"Catalog {source} must be a YAML mapping, got {type(data).__name__}")
    return data


def _benchmark_from_dict(data: dict) -> Benchmark:
    try:
        bench = Benchmark(
            id=data["id"],
            title=data["title"],
            version=str(data.get("version", "")),
            target=data.get("target", "azure"),
            description=data.get("description", ""),
            beta=bool(data.get("beta", False)),
        )
    except KeyError as exc:
        raise CatalogError(f"Missing required key in catalog: {exc}") from exc

    for section_d in data.get("sections", []) or []:
        sec = Section(id=str(section_d["id"]), title=section_d["title"])
        for control_d in section_d.get("controls", []) or []:
            ctrl = Control(
                id=str(control_d["id"]),
                benchmark_id=bench.id,
                section=sec.id,
                title=control_d["title"],
                level=int(control_d.get("level", 1)),
                profile=control_d.get("profile"),
                automated=bool(control_d.get("automated", True)),
                rationale=control_d.get("rationale", ""),
                audit=control_d.get("audit", ""),
                remediation=control_d.get("remediation", ""),
                references=list(control_d.get("references", []) or []),
                tags=list(control_d.get("tags", []) or []),
            )
            sec.controls.append(ctrl)
        bench.sections.append(sec)
    return bench


def load_benchmark(package: str, filename: str = "catalog.yaml") -> Benchmark:
    try:
        files = resources.files(package)
        with resources.as_file(files.joinpath(filename)) as path:
            text = Path(path).read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError) as exc:
        raise CatalogError(f"Catalog {package}/{filename} not found: {exc}") from exc
    data = _load_yaml_text(text, f"{package}/{filename}")
    return _benchmark_from_dict(data)


def load_all_benchmarks(
    packages: Iterable[tuple[str, str]] | None = None,
) -> list[Benchmark]:
    benches: list[Benchmark] = []
    for pkg, fname in (packages or BENCHMARK_PACKAGES):
        try:
            benches.append(load_benchmark(pkg, fname))
        except CatalogError as exc:
            log.error("Failed to load %s: %s", pkg, exc)
    return benches
