from types import SimpleNamespace

from wifi_center.services import hardware_info as hw

LSCPU = """Architecture:                            x86_64
CPU(s):                                  4
Model name:                              Intel(R) Core(TM) i5-2400 CPU @ 3.10GHz
Thread(s) per core:                      1
Core(s) per socket:                      4
Socket(s):                               1
CPU max MHz:                             3400,0000
CPU min MHz:                             1600,0000
Virtualization:                          VT-x
L1d cache:                               128 KiB (4 instances)
L3 cache:                                6 MiB (1 instance)
Vulnerability Itlb multihit:             KVM: Mitigation: Split huge pages
"""
LSPCI = ('01:00.0 "VGA compatible controller" "Advanced Micro Devices, Inc. [AMD/ATI]" "Blackcomb [Radeon HD 6970M/6990M]" -p00\n'
         '00:1b.0 "Audio device" "Intel Corporation" "6 Series HD Audio" -r05\n')
LSBLK = ('{"blockdevices":[{"name":"sda","model":"Samsung SSD 840 EVO 250GB","size":250059350016,"rota":false,"tran":"sata","type":"disk","rm":false},'
         '{"name":"sr0","model":"OPTIARC DVD RW","size":1073741312,"rota":false,"tran":"sata","type":"rom","rm":true},'
         '{"name":"sdb","model":"SD Card Reader","size":0,"rota":true,"tran":"usb","type":"disk","rm":true}]}')
LSUSB = ("Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
         "Bus 001 Device 013: ID 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n\n"
         "Bus 001 Device 008: ID 05ac:0221 Apple, Inc. Aluminum Keyboard (ISO)\n")


def service():
    out = {"lscpu": LSCPU, "lspci": LSPCI, "lsblk": LSBLK, "lsusb": LSUSB}

    def run(argv, timeout):
        text = out[argv[0]]
        if argv[0] == "lsblk" and "rom" not in " ".join(argv) and "-b" not in argv:
            text = LSBLK
        return SimpleNamespace(ok=True, stdout=text)
    return hw.HardwareInfoService(run, sys_root="/nonexistent-sys", proc_root="/nonexistent-proc", which=lambda n: "/usr/bin/" + n)


def test_parsers():
    assert hw.parse_lscpu(LSCPU)["Model name"].startswith("Intel(R) Core(TM) i5-2400")
    rows = hw.parse_lspci_mm(LSPCI)
    assert rows[0]["class"] == "VGA compatible controller" and rows[0]["slot"] == "01:00.0"
    assert [d["name"] for d in hw.parse_lsblk_json(LSBLK)] == ["sda", "sr0", "sdb"] and hw.parse_lsblk_json("nope") == []
    assert hw.parse_lsusb(LSUSB)[1] == ("0cf3:9271", "Qualcomm Atheros Communications AR9271 802.11n")
    assert hw.parse_asound_cards(" 0 [PCH            ]: HDA-Intel - HDA Intel PCH\n   HDA Intel PCH at 0xa8900000 irq 49\n") == ["HDA-Intel - HDA Intel PCH"]
    assert hw.human(1536) == "1.5 KiB" and hw.human(10) == "10 B"
    assert [hw.temp_level(t) for t in (None, 40, 75, 90)] == ["none", "ok", "warm", "hot"]


def test_cpu_section_uses_lscpu_and_sensor_temperature():
    s = service().cpu({"coretemp": [("Package id 0", 61.0), ("Core 0", 58.0), ("Core 1", 59.0)]})
    assert s.headline.startswith("Intel(R) Core") and s.temp == 61.0
    titles = [g.title for g in s.groups]
    assert titles[:2] == ["Processor", "Caches"] and "Core temperatures" in titles and "Security mitigations" in titles


def test_apple_smc_cpu_temperature_fallback():
    s = service().cpu({"applesmc": [("TA0P", 24.8), ("TC0P", 61.5), ("TC0c", 64.0)]})
    assert s.temp == 61.5


def test_storage_graphics_optical_and_peripherals():
    svc = service()
    st = svc.storage({"drivetemp": [("Composite", 33.0)]})
    assert "Samsung SSD 840 EVO" in st.headline and st.temp == 33.0
    disks = [g for g in st.groups if g.items and g.items[0].label == "Device" and g.items[0].value.startswith("/dev/")]
    assert [g.items[2].value for g in disks][0] == "SSD" and all("SD Card" not in g.title for g in st.groups)   # 0-byte reader skipped
    gr = svc.graphics({"radeon": [("temp1", 66.0)]})
    assert "Radeon HD 6970M" in gr.headline and gr.temp == 66.0
    assert svc.optical().headline.startswith("OPTIARC")
    p = svc.peripherals(hw.parse_lsusb(LSUSB))
    assert [i.value for i in p.groups[0].items] == ["Qualcomm Atheros Communications AR9271 802.11n", "Apple, Inc. Aluminum Keyboard (ISO)"]


def test_collect_returns_every_section_even_when_tools_are_missing():
    svc = hw.HardwareInfoService(lambda a, t: SimpleNamespace(ok=False, stdout=""), sys_root="/nonexistent", proc_root="/nonexistent",
                                 which=lambda n: None)
    secs = svc.collect()
    assert [s.id for s in secs] == ["cpu", "memory", "board", "graphics", "storage", "optical", "audio", "network", "peripherals"]
    assert secs[3].headline == "No graphics adapter found" and secs[5].headline == "No optical drive"


def test_speccy_page_builds_summary_and_detail_views(qapp, controller):
    import time

    import pytest
    pytest.importorskip("PySide6")
    from wifi_center.ui.pages.sysinfo_page import SystemInfoPage

    controller.hwinfo = service()
    page = SystemInfoPage(controller)
    end = time.time() + 6
    while time.time() < end and page.nav.count() < 3:
        qapp.processEvents()
        time.sleep(0.02)
    names = [page.nav.item(i).text() for i in range(page.nav.count())]
    assert names[0] == "Summary" and "CPU" in names and "Storage" in names and names[-1] == page.OS_ENTRY
    assert page.stack.count() == page.nav.count()
    page.open_section("storage")
    assert page.nav.currentItem().text() == "Storage" and page.stack.currentIndex() == names.index("Storage")
