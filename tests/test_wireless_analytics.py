from wifi_center.services import wireless_analytics as wa


def ap(i, ssid, f, dbm):
    return {"id": i, "ssid": ssid, "bssid": f"AA:00:00:00:00:{i:02X}", "frequency_mhz": f, "signal_dbm": dbm}


SCANS = [
    {"ts": "t1", "aps": [ap(1, "Home", 2437, -45), ap(2, "Cafe", 2412, -70), ap(3, "Flat-5G", 5180, -55)]},
    {"ts": "t2", "aps": [ap(1, "Home", 2437, -46), ap(2, "Cafe", 2412, -80), ap(4, "NewNet", 5220, -66)]},
    {"ts": "t3", "aps": [ap(1, "Home", 2437, -45), ap(4, "NewNet", 5220, -67)]},
]


def test_activity_events_come_from_real_scan_differences():
    s = wa.summarize_scans(SCANS)
    assert [x.counts for x in s] == [{"2.4 GHz": 2, "5 GHz": 1}, {"2.4 GHz": 2, "5 GHz": 1}, {"2.4 GHz": 1, "5 GHz": 1}]
    assert s[0].events == []                                                             # nothing to compare the first scan with
    kinds2 = sorted((e.kind, e.ssid) for e in s[1].events)
    assert kinds2 == [("appeared", "NewNet"), ("changed", "Cafe"), ("disappeared", "Flat-5G")]     # Home moved only 1 dB: no event
    assert next(e for e in s[1].events if e.kind == "changed").detail == "-70 → -80 dBm"
    assert sorted((e.kind, e.ssid, e.band) for e in s[2].events) == [("disappeared", "Cafe", "2.4 GHz")]
    assert wa.summarize_scans([]) == []                                                  # empty in, empty out


def test_signal_stats():
    st = wa.signal_stats([-50, None, -70, -60])
    assert (st.current, st.minimum, st.maximum, st.samples) == (-60, -70, -50, 3) and round(st.average, 1) == -60.0
    assert wa.signal_stats([]) is None and wa.signal_stats([None]) is None


def test_channel_occupancy_percentages_and_interference():
    rows = [{"channel": 6, "band": "2.4 GHz"}, {"channel": 6, "band": "2.4 GHz"}, {"channel": 7, "band": "2.4 GHz"},
            {"channel": 1, "band": "2.4 GHz"}, {"channel": 36, "band": "5 GHz"}]
    occ = {(c.band, c.channel): c for c in wa.channel_occupancy(rows)}
    assert occ[("2.4 GHz", 6)].count == 2 and occ[("2.4 GHz", 6)].percent == 40.0 and occ[("5 GHz", 36)].percent == 20.0
    assert abs(sum(c.percent for c in occ.values()) - 100.0) < 1e-9
    assert occ[("2.4 GHz", 6)].neighbours == 2        # the other network on 6 plus the one on 7 (channels 1 and 6 are 5 apart: no overlap)
    assert occ[("2.4 GHz", 1)].level == "low" and occ[("5 GHz", 36)].neighbours == 0 and occ[("5 GHz", 36)].level == "low"
    assert wa.channel_occupancy([]) == []
