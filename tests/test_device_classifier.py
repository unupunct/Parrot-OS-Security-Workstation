from wifi_center.services import device_classifier as dc


def test_confirmed_roles_come_from_the_system_not_from_guesses():
    me = dc.classify("192.168.1.5", None, None, None, is_self=True)
    assert (me.device_type, me.basis) == ("This computer", "confirmed")
    g = dc.classify("192.168.1.1", "aa:bb:cc:00:00:01", "Whatever", "pc-lounge", is_gateway=True)
    assert g.device_type == "Gateway / router" and g.basis == "confirmed"


def test_inferences_state_their_reason_and_are_never_confirmed():
    c = dc.classify("192.168.1.30", "00:11:22:33:44:55", "Seiko Epson Corp", None)
    assert (c.device_type, c.basis) == ("Printer", "inferred") and "Epson" in c.reason
    h = dc.classify("192.168.1.31", "00:11:22:33:44:55", None, "Alices-iPhone")
    assert (h.device_type, h.basis) == ("Phone / tablet", "inferred") and "iphone" in h.reason
    assert dc.classify("1.1.1.1", "00:11:22:33:44:55", "TP-LINK TECHNOLOGIES", None).device_type == "Network equipment"
    # a host-name hint beats a vendor hint
    assert dc.classify("x", "00:11:22:33:44:55", "Canon Inc.", "lounge-tv").device_type == "TV / media device"


def test_private_mac_and_unknown():
    assert dc.is_private_mac("02:da:19:33:a5:fb") and dc.is_private_mac("fa:00:00:00:00:00") and not dc.is_private_mac("00:90:a9:e9:74:cf")
    assert dc.classify("x", "02:da:19:33:a5:fb", None, None).device_type == "Private-MAC device"
    assert dc.classify("x", "00:90:a9:e9:74:cf", "Western Digital", None).device_type == "Storage / NAS"
    amb = dc.classify("x", "3c:52:82:71:29:2b", "Hewlett Packard", None)      # HP makes printers, PCs and more: not guessed
    assert (amb.device_type, amb.basis) == ("Unknown", "unknown") and "many kinds" in amb.reason
    assert dc.classify("x", None, None, None).basis == "unknown"
