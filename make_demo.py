#!/usr/bin/env python3
"""make_demo.py — generate demo.kismet, a small SYNTHETIC Kismet log.

Everything in here is invented — the MAC addresses, SSIDs, signals and alerts
are all fabricated so the demo can ship publicly with no real network data. It
writes a genuine kismetdb (same SQLite schema Kismet 2025 uses) so you can try
the scope without a capture of your own:

    python3 make_demo.py
    python3 kismet_graph.py --db demo.kismet -o demo.html

The dataset is deliberately varied to exercise every visualisation: all contact
roles, each encryption tier (open / WEP / WPA2 / WPA3 / WPS), a multi-SSID
"same radio" pair, a phantom client, probe requests, signal-strength spread,
busy-traffic activity, and a couple of IDS alerts.
"""

import json
import sqlite3

PHY = "IEEE802.11"
T0 = 1_751_184_000          # fixed synthetic capture start (arbitrary)
T1 = T0 + 600               # ...and end, ~10 min later


def rrd(vals, start=45):
    """A 60-slot RRD minute-vector with `vals` dropped into the recent slots."""
    mv = [0] * 60
    for i, v in enumerate(vals):
        if start + i < 60:
            mv[start + i] = v
    return {"kismet.common.rrd.minute_vec": mv}


def dev(key, mac, typ, *, name="", manuf="", chan="", freq=0, crypt="",
        sig=None, sig_rrd=None, pkt_rrd=None, packets=0, datasize=0,
        first=T0, last=T1, last_bssid=None, adv=None, assoc=None, probes=None,
        wps=0, country="", ht="", txpower=0):
    """Build one synthetic Kismet device JSON object."""
    d = {
        "kismet.device.base.key": key,
        "kismet.device.base.macaddr": mac,
        "kismet.device.base.type": typ,
        "kismet.device.base.commonname": name or mac,
        "kismet.device.base.name": name,
        "kismet.device.base.manuf": manuf,
        "kismet.device.base.channel": chan,
        "kismet.device.base.frequency": freq,
        "kismet.device.base.crypt": crypt,
        "kismet.device.base.datasize": datasize,
        "kismet.device.base.packets.total": packets,
        "kismet.device.base.first_time": first,
        "kismet.device.base.last_time": last,
    }
    if sig is not None:
        s = {"kismet.common.signal.last_signal": sig,
             "kismet.common.signal.min_signal": sig - 8,
             "kismet.common.signal.max_signal": sig + 4}
        if sig_rrd is not None:
            s["kismet.common.signal.signal_rrd"] = rrd(sig_rrd)
        d["kismet.device.base.signal"] = s
    if pkt_rrd is not None:
        d["kismet.device.base.packets.rrd"] = rrd(pkt_rrd)

    dot11 = {}
    if last_bssid:
        dot11["dot11.device.last_bssid"] = last_bssid
    if adv is None and typ == "Wi-Fi AP" and name:
        adv = name          # an AP advertises its network name by default
    if adv:
        rec = {
            "dot11.advertisedssid.ssid": adv,
            "dot11.advertisedssid.crypt_string": crypt,
            "dot11.advertisedssid.wps_state": wps,
            "dot11.advertisedssid.ht_mode": ht,
            "dot11.advertisedssid.dot11d_country": country,
            "dot11.advertisedssid.advertised_txpower": txpower,
        }
        dot11["dot11.device.advertised_ssid_map"] = [rec]
        dot11["dot11.device.num_advertised_ssids"] = 1
    if assoc:
        dot11["dot11.device.associated_client_map"] = assoc
        dot11["dot11.device.num_associated_clients"] = len(assoc)
    if probes:
        dot11["dot11.device.probed_ssid_map"] = [
            {"dot11.probedssid.ssid": p} for p in probes]
        dot11["dot11.device.num_probed_ssids"] = len(probes)
    if dot11:
        d["dot11.device"] = dot11
    return d


# --- MACs (all locally-administered / synthetic) ---------------------------
HOME   = "AA:BB:CC:00:00:10"
CAFE   = "AA:BB:CC:00:00:20"
OLD    = "AA:BB:CC:00:00:30"
FIBER  = "AA:BB:CC:00:00:40"
MESH1  = "DD:EE:FF:11:22:01"     # same radio as...
MESH2  = "DD:EE:FF:11:22:02"     # ...this one (prefix matches, co-channel)
LAPTOP = "11:22:33:00:00:A1"
PHONE  = "11:22:33:00:00:A2"
GHOST  = "11:22:33:00:00:99"     # referenced by HomeNet but never captured -> phantom
TABLET = "11:22:33:00:00:C1"
IOT    = "11:22:33:00:00:D1"
DESKTP = "11:22:33:00:00:E1"
MCLIENT= "11:22:33:00:00:F1"
BRIDGE = "11:22:33:00:00:B1"
ADHOC  = "22:33:44:00:00:01"
UNKNOWN= "33:44:55:00:00:01"
SPOOF  = "DE:AD:BE:EF:00:99"     # named only by an alert -> unlinked alert

WPA2 = "WPA2 WPA2-PSK AES-CCMP"

devices = [
    # ----- access points, one per encryption tier -----
    dev("AP_HOME", HOME, "Wi-Fi AP", name="HomeNet", manuf="Netgear",
        chan="6", freq=2_437_000, crypt=WPA2, wps=1, country="SE", ht="HT40",
        txpower=20, sig=-48, packets=48200, datasize=32_500_000,
        sig_rrd=[-52,-50,-49,-48,-47,-49,-48], pkt_rrd=[40,55,48,60,52,44,58],
        assoc={LAPTOP: "CL_LAPTOP", PHONE: "CL_PHONE", GHOST: "phantom"}),
    dev("AP_CAFE", CAFE, "Wi-Fi AP", name="CoffeeShop", manuf="Ubiquiti Inc",
        chan="11", freq=2_462_000, crypt="Open", country="SE", ht="HT20",
        txpower=17, sig=-64, packets=9100, assoc={TABLET: "CL_TABLET"}),
    dev("AP_OLD", OLD, "Wi-Fi AP", name="OldRouter", manuf="D-Link",
        chan="1", freq=2_412_000, crypt="WEP", ht="HT20", txpower=15,
        sig=-79, packets=1300, last=T0 + 400, assoc={IOT: "CL_IOT"}),
    dev("AP_FIBER", FIBER, "Wi-Fi AP", name="SecureNet", manuf="Cisco",
        chan="36", freq=5_180_000, crypt="WPA3 WPA3-SAE", country="SE",
        ht="VHT80", txpower=23, sig=-44, packets=22400, datasize=18_000_000,
        assoc={DESKTP: "CL_DESKTOP"}),
    # ----- a multi-SSID router: two BSSIDs on one radio (co-channel) -----
    dev("AP_MESH1", MESH1, "Wi-Fi AP", name="Mesh-Main", manuf="TP-Link",
        chan="6", freq=2_437_000, crypt=WPA2, country="SE", ht="HT40",
        txpower=20, sig=-58, packets=15300, assoc={MCLIENT: "CL_MESH"}),
    dev("AP_MESH2", MESH2, "Wi-Fi AP", name="Mesh-Guest", manuf="TP-Link",
        chan="6", freq=2_437_000, crypt=WPA2, country="SE", ht="HT40",
        txpower=20, sig=-59, packets=800),

    # ----- clients (signal spread drives the gauge colours) -----
    dev("CL_LAPTOP", LAPTOP, "Wi-Fi Client", name="", manuf="Apple",
        chan="6", freq=2_437_000, sig=-53, packets=41000, datasize=30_000_000,
        sig_rrd=[-58,-55,-54,-53,-52,-54,-53], pkt_rrd=[35,50,42,55,48,40,52],
        last_bssid=HOME),
    dev("CL_PHONE", PHONE, "Wi-Fi Client", name="", manuf="Samsung",
        chan="6", freq=2_437_000, sig=-69, packets=6200, last_bssid=HOME,
        probes=["HomeNet", "Starbucks"]),
    dev("CL_TABLET", TABLET, "Wi-Fi Client", manuf="Amazon",
        chan="11", freq=2_462_000, sig=-76, packets=3100, last_bssid=CAFE),
    dev("CL_IOT", IOT, "Wi-Fi Client", manuf="Espressif", chan="1",
        freq=2_412_000, sig=-86, packets=420, last=T0 + 150, last_bssid=OLD),
    dev("CL_DESKTOP", DESKTP, "Wi-Fi Client", manuf="Intel", chan="36",
        freq=5_180_000, sig=-46, packets=19800, datasize=15_000_000,
        pkt_rrd=[22,30,26,33,28,24,31], last_bssid=FIBER),
    dev("CL_MESH", MCLIENT, "Wi-Fi Client", manuf="Google", chan="6",
        freq=2_437_000, sig=-61, packets=5400, last_bssid=MESH1),

    # ----- other roles -----
    dev("BR_TV", BRIDGE, "Wi-Fi Bridged", name="LivingRoomTV", manuf="Sony",
        chan="6", freq=2_437_000, sig=-57, packets=8700, last_bssid=HOME),
    dev("AD_CAM", ADHOC, "Wi-Fi Ad-Hoc", name="GoPro-Link", manuf="GoPro",
        chan="6", freq=2_437_000, sig=-71, packets=2100, last=T0 + 300),
    dev("DV_ROAM", UNKNOWN, "Wi-Fi Device", manuf="Murata", chan="",
        sig=-82, packets=300, last=T0 + 200, probes=["FreeWiFi"]),
]

alerts = [
    {"kismet.alert.header": "DEAUTHFLOOD", "kismet.alert.severity": 10,
     "kismet.alert.timestamp": T1 - 30, "kismet.alert.channel": "6",
     "kismet.alert.transmitter_mac": HOME,
     "kismet.alert.text": "Deauthenticate/Disassociate flood on " + HOME +
                          " — possible denial-of-service attack"},
    {"kismet.alert.header": "APSPOOF", "kismet.alert.severity": 5,
     "kismet.alert.timestamp": T1 - 90, "kismet.alert.channel": "6",
     "kismet.alert.transmitter_mac": SPOOF,
     "kismet.alert.text": "Possible AP spoof: BSSID " + SPOOF +
                          " advertising known SSID HomeNet"},
]


def strongest(d):
    s = d.get("kismet.device.base.signal", {})
    return s.get("kismet.common.signal.max_signal", 0) or 0


def main(path="demo.kismet"):
    con = sqlite3.connect(path)
    con.executescript("""
        DROP TABLE IF EXISTS KISMET; DROP TABLE IF EXISTS devices;
        DROP TABLE IF EXISTS alerts;
        CREATE TABLE KISMET (kismet_version TEXT, db_version INT, db_module TEXT);
        CREATE TABLE devices (first_time INT, last_time INT, devkey TEXT,
            phyname TEXT, devmac TEXT, strongest_signal INT, min_lat REAL,
            min_lon REAL, max_lat REAL, max_lon REAL, avg_lat REAL, avg_lon REAL,
            bytes_data INT, type TEXT, device BLOB,
            UNIQUE(phyname, devmac) ON CONFLICT REPLACE);
        CREATE TABLE alerts (ts_sec INT, ts_usec INT, phyname TEXT, devmac TEXT,
            lat REAL, lon REAL, header TEXT, json BLOB);
    """)
    con.execute("INSERT INTO KISMET VALUES (?,?,?)",
                ("2025.09.0-demo", 9, "kismetlog"))
    for d in devices:
        con.execute(
            "INSERT INTO devices (first_time,last_time,devkey,phyname,devmac,"
            "strongest_signal,bytes_data,type,device) VALUES (?,?,?,?,?,?,?,?,?)",
            (d["kismet.device.base.first_time"], d["kismet.device.base.last_time"],
             d["kismet.device.base.key"], PHY, d["kismet.device.base.macaddr"],
             strongest(d), d["kismet.device.base.datasize"],
             d["kismet.device.base.type"], json.dumps(d).encode("utf-8")))
    for a in alerts:
        con.execute(
            "INSERT INTO alerts (ts_sec,ts_usec,phyname,devmac,header,json)"
            " VALUES (?,?,?,?,?,?)",
            (int(a["kismet.alert.timestamp"]), 0, PHY,
             a["kismet.alert.transmitter_mac"], a["kismet.alert.header"],
             json.dumps(a).encode("utf-8")))
    con.commit()
    con.close()
    print(f"Wrote {path}: {len(devices)} devices, {len(alerts)} alerts")


if __name__ == "__main__":
    main()
