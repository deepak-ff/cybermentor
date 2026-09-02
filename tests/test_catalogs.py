"""Smoke tests for the bundled benchmark catalogs."""

from __future__ import annotations

from secbench.engine import load_all_benchmarks


def test_all_catalogs_load():
    benches = load_all_benchmarks()
    expected = {
        "azure_foundations_6_0_0",
        "azure_compute_2_0_0",
        "azure_database_2_0_0",
        "azure_storage_1_0_0",
        "m365_foundations_6_0_1",
        "macos_tahoe_1_0_0",
        "rhel_10_1_0_1",
        "rhel_9_2_0_0",
        "rhel_9_stig_1_0_0",
        "rhel_8_4_0_0",
        "rhel_8_stig_2_0_0",
        "defender_av_1_0_0",
        "windows_11_enterprise_5_0_1",
        "windows_11_standalone_5_0_0",
        "azure_compute_win_server_2022_1_0_0",
        "azure_compute_win_server_2019_1_0_0",
        "win_server_2025_2_0_0",
        "win_server_2025_standalone_1_0_0",
        "win_server_2022_5_0_0",
        "win_server_2022_standalone_2_0_0",
        "win_server_2022_stig_2_0_0",
        "win_server_2019_4_0_0",
        "win_server_2019_standalone_3_0_0",
        "win_server_2019_stig_3_0_0",
    }
    found = {b.id for b in benches}
    assert expected.issubset(found), f"Missing benchmarks: {expected - found}"


def test_each_benchmark_has_controls():
    for b in load_all_benchmarks():
        assert b.sections, f"{b.id} has no sections"
        assert b.all_controls(), f"{b.id} has no controls"
        for c in b.all_controls():
            assert c.id, f"control without id in {b.id}"
            assert c.title, f"control {c.id} has no title"
            assert c.level in (1, 2), f"control {c.id} has invalid level {c.level}"
            assert c.benchmark_id == b.id


def test_total_control_count_reasonable():
    total = sum(len(b.all_controls()) for b in load_all_benchmarks())
    # Sanity check: we ship at least 400 controls.
    assert total >= 400, f"Only {total} controls loaded"
