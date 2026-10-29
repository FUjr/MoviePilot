"""
验证本地站点资源按解释器 ABI 筛选及事务式替换。
"""

import importlib.util
import sys
import uuid
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "local_setup.py"


def load_local_setup_module():
    """
    以隔离模块名加载本地安装脚本，避免测试间共享模块状态。
    """
    module_name = f"moviepilot_local_setup_resources_{uuid.uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("gil_disabled", "suffix"),
    [
        (0, ""),
        (1, "t"),
    ],
)
def test_python_version_tag_distinguishes_free_threaded_abi(
    monkeypatch, gil_disabled, suffix
):
    """
    解释器版本标签区分普通构建与自由线程 ABI。
    """
    module = load_local_setup_module()
    monkeypatch.setattr(
        module.sysconfig,
        "get_config_var",
        lambda name: gil_disabled if name == "Py_GIL_DISABLED" else None,
    )

    expected = f"cp{sys.version_info.major}{sys.version_info.minor}{suffix}"
    assert module._get_python_version_tag() == expected


@pytest.mark.parametrize(
    ("platform_tag", "machine", "python_version", "expected"),
    [
        (
            "linux",
            "x86_64",
            "cp314",
            "sites.cpython-314-x86_64-linux-gnu.so",
        ),
        (
            "linux",
            "x86_64",
            "cp314t",
            "sites.cpython-314t-x86_64-linux-gnu.so",
        ),
        (
            "linux",
            "aarch64",
            "cp314",
            "sites.cpython-314-aarch64-linux-gnu.so",
        ),
        (
            "linux",
            "aarch64",
            "cp314t",
            "sites.cpython-314t-aarch64-linux-gnu.so",
        ),
        ("darwin", "arm64", "cp314", "sites.cpython-314-darwin.so"),
        ("darwin", "arm64", "cp314t", "sites.cpython-314t-darwin.so"),
        ("windows", "amd64", "cp314", "sites.cp314-win_amd64.pyd"),
        ("windows", "amd64", "cp314t", "sites.cp314t-win_amd64.pyd"),
    ],
)
def test_filter_resources_files_selects_exact_runtime_artifact(
    tmp_path, platform_tag, machine, python_version, expected
):
    """
    资源筛选只保留站点数据和精确匹配运行时的原生扩展。
    """
    module = load_local_setup_module()
    filenames = {
        "user.sites.v3.bin",
        "sites.pyi",
        "sites.cpython-314-x86_64-linux-gnu.so",
        "sites.cpython-314-aarch64-linux-gnu.so",
        "sites.cpython-314t-x86_64-linux-gnu.so",
        "sites.cpython-314t-aarch64-linux-gnu.so",
        "sites.cpython-314-darwin.so",
        "sites.cpython-314t-darwin.so",
        "sites.cp314-win_amd64.pyd",
        "sites.cp314t-win_amd64.pyd",
    }
    for filename in filenames:
        (tmp_path / filename).write_bytes(filename.encode())

    matched = module._filter_resources_files(
        tmp_path,
        platform_tag,
        machine,
        python_version,
    )

    assert [path.name for path in matched] == ["user.sites.v3.bin", expected]


def test_copy_resource_files_keeps_only_current_runtime_artifact(
    monkeypatch, tmp_path
):
    """
    复制资源后仅保留当前运行时扩展、站点数据和类型声明。
    """
    module = load_local_setup_module()
    source_dir = tmp_path / "resources.v3"
    target_dir = tmp_path / "site"
    source_dir.mkdir()
    target_dir.mkdir()
    for filename in (
        "user.sites.v3.bin",
        "sites.cpython-314-x86_64-linux-gnu.so",
        "sites.cpython-314-aarch64-linux-gnu.so",
        "sites.cpython-314t-x86_64-linux-gnu.so",
    ):
        (source_dir / filename).write_text(f"source:{filename}", encoding="utf-8")
    (target_dir / "sites.pyi").write_text("typing", encoding="utf-8")
    (target_dir / "sites.cpython-313-x86_64-linux-gnu.so").write_text(
        "stale", encoding="utf-8"
    )
    (target_dir / "sites.cp314-win_amd64.pyd").write_text(
        "stale", encoding="utf-8"
    )
    (target_dir / "sites.cpython-314t-darwin.so").write_text(
        "stale", encoding="utf-8"
    )
    (target_dir / "sites.legacy.dylib").write_text("stale", encoding="utf-8")
    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", target_dir)
    monkeypatch.setattr(module, "_get_platform_tag", lambda: ("linux", "x86_64"))
    monkeypatch.setattr(module, "_get_python_version_tag", lambda: "cp314t")

    copied = module.copy_resource_files(source_dir)

    assert copied == [
        "user.sites.v3.bin",
        "sites.cpython-314t-x86_64-linux-gnu.so",
    ]
    assert sorted(path.name for path in target_dir.iterdir()) == [
        "sites.cpython-314t-x86_64-linux-gnu.so",
        "sites.pyi",
        "user.sites.v3.bin",
    ]


def test_copy_resource_files_rejects_partial_source_before_changing_target(
    monkeypatch, tmp_path
):
    """
    源资源不完整时，在修改目标前拒绝操作并保留旧资源。
    """
    module = load_local_setup_module()
    source_dir = tmp_path / "resources.v3"
    target_dir = tmp_path / "site"
    source_dir.mkdir()
    target_dir.mkdir()
    (source_dir / "user.sites.v3.bin").write_bytes(b"new-data")
    old_native = target_dir / "sites.cpython-314-darwin.so"
    old_data = target_dir / "user.sites.v3.bin"
    old_native.write_bytes(b"old-native")
    old_data.write_bytes(b"old-data")
    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", target_dir)
    monkeypatch.setattr(module, "_get_platform_tag", lambda: ("darwin", "arm64"))
    monkeypatch.setattr(module, "_get_python_version_tag", lambda: "cp314t")

    with pytest.raises(RuntimeError, match="sites.cpython-314t-darwin.so"):
        module.copy_resource_files(source_dir)

    assert old_native.read_bytes() == b"old-native"
    assert old_data.read_bytes() == b"old-data"


def test_copy_resource_files_keeps_target_when_staging_fails(monkeypatch, tmp_path):
    """
    资源暂存失败时保留目标内容，并清理临时目录。
    """
    module = load_local_setup_module()
    source_dir = tmp_path / "resources.v3"
    target_dir = tmp_path / "site"
    source_dir.mkdir()
    target_dir.mkdir()
    (source_dir / "user.sites.v3.bin").write_bytes(b"new-data")
    new_native_name = "sites.cpython-314t-darwin.so"
    (source_dir / new_native_name).write_bytes(b"new-native")
    old_native = target_dir / "sites.cpython-314-darwin.so"
    old_data = target_dir / "user.sites.v3.bin"
    old_native.write_bytes(b"old-native")
    old_data.write_bytes(b"old-data")
    real_copy2 = module.shutil.copy2

    def fail_native_staging(source, target):
        if Path(source).name == new_native_name:
            raise OSError("injected native staging failure")
        return real_copy2(source, target)

    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", target_dir)
    monkeypatch.setattr(module, "_get_platform_tag", lambda: ("darwin", "arm64"))
    monkeypatch.setattr(module, "_get_python_version_tag", lambda: "cp314t")
    monkeypatch.setattr(module.shutil, "copy2", fail_native_staging)

    with pytest.raises(OSError, match="injected native staging failure"):
        module.copy_resource_files(source_dir)

    assert old_native.read_bytes() == b"old-native"
    assert old_data.read_bytes() == b"old-data"
    assert not (target_dir / new_native_name).exists()
    assert not list(target_dir.glob(".sites-sync-*"))


def test_copy_resource_files_rolls_back_when_commit_fails(monkeypatch, tmp_path):
    """
    资源替换提交失败时恢复旧扩展和数据文件。
    """
    module = load_local_setup_module()
    source_dir = tmp_path / "resources.v3"
    target_dir = tmp_path / "site"
    source_dir.mkdir()
    target_dir.mkdir()
    (source_dir / "user.sites.v3.bin").write_bytes(b"new-data")
    new_native_name = "sites.cpython-314t-darwin.so"
    (source_dir / new_native_name).write_bytes(b"new-native")
    old_native = target_dir / "sites.cpython-314-darwin.so"
    old_data = target_dir / "user.sites.v3.bin"
    old_native.write_bytes(b"old-native")
    old_data.write_bytes(b"old-data")
    real_replace = module.os.replace

    def fail_native_commit(source, target):
        if Path(source).parent.name == "staging" and Path(target).name == new_native_name:
            raise OSError("injected native commit failure")
        return real_replace(source, target)

    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", target_dir)
    monkeypatch.setattr(module, "_get_platform_tag", lambda: ("darwin", "arm64"))
    monkeypatch.setattr(module, "_get_python_version_tag", lambda: "cp314t")
    monkeypatch.setattr(module.os, "replace", fail_native_commit)

    with pytest.raises(OSError, match="injected native commit failure"):
        module.copy_resource_files(source_dir)

    assert old_native.read_bytes() == b"old-native"
    assert old_data.read_bytes() == b"old-data"
    assert not (target_dir / new_native_name).exists()


def test_local_resource_status_requires_source_bundle(monkeypatch, tmp_path):
    """
    源码包就绪判定与 Python ABI 无关，缺少任一源码资源均不能跳过安装。
    """
    module = load_local_setup_module()
    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", tmp_path)
    (tmp_path / "user.sites.v3.bin").write_bytes(b"data")
    (tmp_path / "sites.cpython-314t-darwin.so").write_bytes(b"native")
    assert module.local_resource_status() is False
    (tmp_path / "sites.py").write_text("# 源码实现\n", encoding="utf-8")
    assert module.local_resource_status() is False
    (tmp_path / "user.sites.v3.json").write_text("{}", encoding="utf-8")
    assert module.local_resource_status() is True


def test_install_resources_preserves_source_and_removes_native_shadowing(monkeypatch, tmp_path):
    """
    初始化保持源码原样，清除所有 ABI 的旧资源并禁止下载。
    """
    module = load_local_setup_module()
    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", tmp_path)
    monkeypatch.setattr(module, "ensure_local_dirs", lambda: None)
    (tmp_path / "sites.py").write_text("# 本地实现\n", encoding="utf-8")
    (tmp_path / "sites.pyi").write_text("# 类型声明\n", encoding="utf-8")
    (tmp_path / "user.sites.v3.json").write_text("{}", encoding="utf-8")
    (tmp_path / "sites.cpython-314t-darwin.so").write_bytes(b"native")
    (tmp_path / "user.sites.v3.bin").write_bytes(b"data")
    assert module.install_resources(None, None) == ["sites.py", "user.sites.v3.json"]
    assert sorted(path.name for path in tmp_path.iterdir()) == ["sites.py", "sites.pyi", "user.sites.v3.json"]


def test_install_incomplete_source_keeps_existing_resource(monkeypatch, tmp_path):
    """
    源码不完整时先报错，不能删除仍在使用的旧资源。
    """
    module = load_local_setup_module()
    monkeypatch.setattr(module, "SITE_RESOURCE_DIR", tmp_path)
    monkeypatch.setattr(module, "ensure_local_dirs", lambda: None)
    old = tmp_path / "sites.cpython-314t-darwin.so"
    old.write_bytes(b"native")
    with pytest.raises(RuntimeError, match="本地站点资源"):
        module.install_resources(None, None)
    assert old.read_bytes() == b"native"
