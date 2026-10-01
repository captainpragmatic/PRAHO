"""Regression tests for scripts/screenshot_diff.py's non-browser logic: pixel diffing, URL
slugging, and batch comparison. The capture path needs a live browser and stack (covered by
running the script directly against the e2e stack, per its own docstring); everything here
runs with no network and no browser.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from PIL import Image


def _load_module():
    repo_root = Path(__file__).resolve().parents[2]
    module_path = repo_root / "scripts" / "screenshot_diff.py"
    spec = importlib.util.spec_from_file_location("screenshot_diff", module_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def sd():
    return _load_module()


def _solid_png(path: Path, size: tuple[int, int], color: tuple[int, int, int]) -> None:
    Image.new("RGB", size, color).save(path)


class TestDiff:
    def test_identical_images_diff_to_zero(self, sd, tmp_path):
        a = tmp_path / "a.png"
        b = tmp_path / "b.png"
        _solid_png(a, (10, 10), (255, 0, 0))
        _solid_png(b, (10, 10), (255, 0, 0))
        assert sd.diff(a, b, None) == 0

    def test_different_images_diff_to_a_positive_count(self, sd, tmp_path):
        a = tmp_path / "a.png"
        b = tmp_path / "b.png"
        _solid_png(a, (10, 10), (255, 0, 0))
        _solid_png(b, (10, 10), (0, 255, 0))
        assert sd.diff(a, b, None) == 100

    def test_partial_difference_counts_only_the_changed_region(self, sd, tmp_path):
        a = tmp_path / "a.png"
        b = tmp_path / "b.png"
        img_a = Image.new("RGB", (10, 10), (255, 0, 0))
        img_b = img_a.copy()
        for x in range(3):
            for y in range(3):
                img_b.putpixel((x, y), (0, 0, 0))
        img_a.save(a)
        img_b.save(b)
        assert sd.diff(a, b, None) == 9

    def test_size_mismatch_returns_none_not_a_negative_number(self, sd, tmp_path):
        a = tmp_path / "a.png"
        b = tmp_path / "b.png"
        _solid_png(a, (10, 10), (255, 0, 0))
        _solid_png(b, (10, 20), (255, 0, 0))
        assert sd.diff(a, b, None) is None

    def test_diff_image_is_written_only_when_something_differs(self, sd, tmp_path):
        a = tmp_path / "a.png"
        b = tmp_path / "b.png"
        out = tmp_path / "diff.png"
        _solid_png(a, (10, 10), (255, 0, 0))
        _solid_png(b, (10, 10), (255, 0, 0))
        sd.diff(a, b, out)
        assert not out.exists()

        _solid_png(b, (10, 10), (0, 255, 0))
        sd.diff(a, b, out)
        assert out.exists()


class TestSlug:
    def test_distinct_query_strings_do_not_collide(self, sd):
        first = sd._slug("http://localhost:8701/billing/invoices/?page=1")
        second = sd._slug("http://localhost:8701/billing/invoices/?page=2")
        assert first != second

    def test_path_segment_boundary_does_not_collide_with_underscore(self, sd):
        first = sd._slug("http://localhost:8701/a/b/")
        second = sd._slug("http://localhost:8701/a_b/")
        assert first != second

    def test_same_url_produces_the_same_slug_every_time(self, sd):
        url = "http://localhost:8701/services/1/usage/"
        assert sd._slug(url) == sd._slug(url)


class TestBatchDiff:
    def test_matching_pairs_report_zero_changed(self, sd, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(before_dir / "page.png", (5, 5), (1, 2, 3))
        _solid_png(after_dir / "page.png", (5, 5), (1, 2, 3))

        results, missing = sd.batch_diff(before_dir, after_dir, None)

        assert results == {"page.png": 0}
        assert missing == set()

    def test_a_file_only_in_before_is_reported_as_missing_not_silently_dropped(self, sd, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(before_dir / "orphan.png", (5, 5), (1, 2, 3))

        results, missing = sd.batch_diff(before_dir, after_dir, None)

        assert results == {}
        assert missing == {"orphan.png"}

    def test_a_file_only_in_after_is_also_reported_as_missing(self, sd, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(after_dir / "new_page.png", (5, 5), (1, 2, 3))

        results, missing = sd.batch_diff(before_dir, after_dir, None)

        assert results == {}
        assert missing == {"new_page.png"}


class TestMainExitCodes:
    """The CLI layer: batch-diff must fail the run when there is a real change, a missing
    counterpart, or nothing at all to compare - all four were silent exit-0 before this fix."""

    def _run_batch_diff(self, sd, monkeypatch, before_dir, after_dir):
        monkeypatch.setattr(
            sys, "argv", ["screenshot_diff.py", "batch-diff", "--before-dir", str(before_dir), "--after-dir", str(after_dir)]
        )
        return sd.main()

    def test_no_changes_exits_0(self, sd, monkeypatch, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(before_dir / "page.png", (5, 5), (1, 2, 3))
        _solid_png(after_dir / "page.png", (5, 5), (1, 2, 3))

        assert self._run_batch_diff(sd, monkeypatch, before_dir, after_dir) == 0

    def test_a_real_change_exits_1(self, sd, monkeypatch, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(before_dir / "page.png", (5, 5), (1, 2, 3))
        _solid_png(after_dir / "page.png", (5, 5), (9, 9, 9))

        assert self._run_batch_diff(sd, monkeypatch, before_dir, after_dir) == 1

    def test_a_missing_counterpart_exits_1(self, sd, monkeypatch, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()
        _solid_png(before_dir / "page.png", (5, 5), (1, 2, 3))

        assert self._run_batch_diff(sd, monkeypatch, before_dir, after_dir) == 1

    def test_a_nonexistent_directory_exits_1(self, sd, monkeypatch, tmp_path):
        after_dir = tmp_path / "after"
        after_dir.mkdir()

        assert self._run_batch_diff(sd, monkeypatch, tmp_path / "does-not-exist", after_dir) == 1

    def test_two_empty_directories_exit_1_not_a_silent_pass(self, sd, monkeypatch, tmp_path):
        before_dir = tmp_path / "before"
        after_dir = tmp_path / "after"
        before_dir.mkdir()
        after_dir.mkdir()

        assert self._run_batch_diff(sd, monkeypatch, before_dir, after_dir) == 1
