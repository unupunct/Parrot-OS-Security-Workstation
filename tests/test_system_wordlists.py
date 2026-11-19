import os

import pytest

from wifi_center.services import system_wordlists as sw


def test_lists_folders_then_files_with_link_targets(tmp_path):
    (tmp_path / "rockyou.txt").write_bytes(b"a" + bytes([10]) + b"b" + bytes([10]) + b"c" + bytes([10]))
    (tmp_path / "rockyou.txt.gz").write_bytes(b"x" * 10)
    real = tmp_path / "real" / "lists"
    real.mkdir(parents=True)
    (real / "one.txt").write_text("x\n")
    try:
        os.symlink(real, tmp_path / "dirb")
        os.symlink(tmp_path / "rockyou.txt", tmp_path / "rock.lst")
        os.symlink(tmp_path / "missing", tmp_path / "gone")
    except OSError:
        pytest.skip("symlinks not permitted here")
    e = {x.name: x for x in sw.list_folder(str(tmp_path))}
    assert e["dirb"].is_dir and e["dirb"].children == 1 and e["dirb"].target.endswith(str(real)[-12:])
    assert e["rock.lst"].kind == "file" and e["rock.lst"].size == 6 and e["rock.lst"].target
    assert e["rockyou.txt.gz"].compressed and not e["rockyou.txt"].compressed
    assert e["gone"].kind == "broken"
    names = [x.name for x in sw.list_folder(str(tmp_path))]
    assert names.index("dirb") < names.index("rockyou.txt")           # folders first


def test_line_count_and_missing_folder(tmp_path):
    f = tmp_path / "w.txt"
    f.write_bytes(b"a" + bytes([10]) + b"b" + bytes([10]) + b"c" + bytes([10]))
    assert sw.line_count(str(f)) == 3 and sw.line_count(str(tmp_path / "x.gz")) is None
    assert sw.list_folder(str(tmp_path / "nope")) == []


def test_plan_copy_resolves_links_flattens_and_caps(tmp_path):
    a = tmp_path / "real"
    (a / "sub").mkdir(parents=True)
    (a / "one.txt").write_bytes(b"x" * 5)
    (a / "sub" / "two.txt").write_bytes(b"y" * 7)
    (a / "sub" / "deep").mkdir()
    (a / "sub" / "deep" / "three.txt").write_bytes(b"z")          # deeper than MAX_COPY_DEPTH: left out
    single = tmp_path / "list.txt"
    single.write_bytes(b"q" * 3)
    plan = sw.plan_copy([str(a), str(single)])
    got = {(i.folder, i.name): i.size for i in plan.items}
    assert got == {("real", "one.txt"): 5, ("real", "sub_two.txt"): 7, ("", "list.txt"): 3}
    assert plan.total == 15 and not plan.truncated
    capped = sw.plan_copy([str(a)], max_files=1)
    assert len(capped.items) == 1 and capped.truncated
    assert sw.plan_copy([str(tmp_path / "missing")]).skipped
