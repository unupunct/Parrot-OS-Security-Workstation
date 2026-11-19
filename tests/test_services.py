import pytest

from wifi_center.services.adapter_service import AdapterService, parse_iw_phy_info
from wifi_center.services.process_runner import run_command
from wifi_center.services.system_service import SystemService, parse_apt_simulation, parse_os_release

OS_RELEASE = '''PRETTY_NAME="Parrot Security 6.2 (lory)"
NAME="Parrot Security"
ID=parrot
ID_LIKE=debian
# comment
'''

IW_PHY = """Wiphy phy0
\tmax # scan SSIDs: 20
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (20.0 dBm)
\t\t\t* 2437.0 MHz [6] (20.0 dBm)
\tBand 2:
\t\tFrequencies:
\t\t\t* 5180.0 MHz [36] (23.0 dBm)
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * monitor
Wiphy phy1
\tBand 1:
\t\tFrequencies:
\t\t\t* 2412.0 MHz [1] (20.0 dBm)
\tSupported interface modes:
\t\t * managed
"""


def test_parse_os_release():
    d = parse_os_release(OS_RELEASE)
    assert d["PRETTY_NAME"] == "Parrot Security 6.2 (lory)" and d["ID"] == "parrot"


def test_os_info_detects_parrot(tmp_path):
    f = tmp_path / "os-release"
    f.write_text(OS_RELEASE)
    assert SystemService(f).os_info().is_parrot
    f.write_text("PRETTY_NAME=Ubuntu\nID=ubuntu\nID_LIKE=debian\n")
    assert not SystemService(f).os_info().is_parrot


def test_missing_os_release_falls_back(tmp_path):
    info = SystemService(tmp_path / "nope").os_info()
    assert info.pretty_name and not info.is_parrot


def test_parse_apt_simulation():
    out = "Inst libc6 [1] (2 x)\nInst foo [1] (2 x)\nRemv bar [1]\nConf libc6\n"
    assert parse_apt_simulation(out) == {"upgrade": 2, "remove": 1}
    assert parse_apt_simulation("") == {"upgrade": 0, "remove": 0}


def test_pending_updates_none_without_apt(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: None)
    assert SystemService().pending_updates() is None


def test_metrics_are_sane():
    s = SystemService()
    used, total, pct = s.memory()
    assert 0 < used <= total and 0 <= pct <= 100
    assert s.uptime_seconds() > 0
    assert 0 <= s.disk().percent <= 100


def test_parse_iw_phy():
    phys = parse_iw_phy_info(IW_PHY)
    assert phys["phy0"]["bands"] == ["2.4 GHz", "5 GHz"]
    assert "monitor" in phys["phy0"]["modes"]
    assert phys["phy1"]["modes"] == ["managed"]


def test_adapter_detect_from_fake_sysfs(tmp_path, monkeypatch):
    net = tmp_path / "net"
    (net / "wlan0" / "wireless").mkdir(parents=True)
    (net / "wlan0" / "operstate").write_text("up\n")
    (net / "wlan0" / "address").write_text("aa:bb:cc:dd:ee:ff\n")
    (net / "eth0").mkdir()
    monkeypatch.setattr("shutil.which", lambda _: None)  # no iw/lsusb
    found = AdapterService(net).detect()
    assert [a.interface for a in found] == ["wlan0"]
    assert found[0].state == "up" and found[0].monitor_capable is None


def test_adapter_unsupported_platform(tmp_path):
    svc = AdapterService(tmp_path / "missing")
    assert not svc.supported() and svc.detect() == []


def test_run_command_rejects_bad_args():
    with pytest.raises(TypeError):
        run_command("ls -l")  # a string, not an arg list
    with pytest.raises(ValueError):
        run_command(["echo", "a\x00b"])


def test_run_command_no_shell_injection(tmp_path):
    import sys
    marker = tmp_path / "pwned"
    r = run_command([sys.executable, "-c", "import sys; print(sys.argv[1])", f"x; touch {marker}"])
    assert r.ok and not marker.exists()


def test_run_command_missing_and_timeout():
    import sys
    assert run_command(["definitely-not-a-real-binary-xyz"]).error
    r = run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert r.timed_out and not r.ok
