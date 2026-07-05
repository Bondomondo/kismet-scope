#!/usr/bin/env python3
"""
kismet_graph.py — build an interactive device-relationship "scope" from Kismet data.

Reads either a Kismet log database (.kismetdb, SQLite) or a live Kismet REST API,
extracts Wi-Fi devices and how they relate (AP <-> associated clients, and
optionally the SSID networks they advertise / probe for), and writes a single
self-contained interactive HTML visualisation.

Examples
--------
  # From a capture log:
  python3 kismet_graph.py --db Kismet-20260703.kismetdb -o scope.html

  # From a running Kismet server (basic auth), only devices seen in the last 15 min:
  python3 kismet_graph.py --api http://cannon.local:2501 \
      --user admin --password secret --active-since 900 -o scope.html

  # Using an API key instead of user/password:
  python3 kismet_graph.py --api http://127.0.0.1:2501 --apikey ABCDEF... -o scope.html

No third-party Python packages required (stdlib only).
"""

import argparse
import gzip
import json
import os
import socket
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import request as urlrequest, parse as urlparse, error as urlerror
import base64

# ---------------------------------------------------------------------------
# Fields we ask the API for (nested paths preserve hierarchy, so the same
# extract() walker works on both API responses and full DB device JSON).
# ---------------------------------------------------------------------------
API_FIELDS = [
    "kismet.device.base.key",
    "kismet.device.base.macaddr",
    "kismet.device.base.type",
    "kismet.device.base.commonname",
    "kismet.device.base.name",
    "kismet.device.base.manuf",
    "kismet.device.base.channel",
    "kismet.device.base.frequency",
    "kismet.device.base.crypt",
    "kismet.device.base.datasize",
    "kismet.device.base.packets.total",
    "kismet.device.base.first_time",
    "kismet.device.base.last_time",
    # Request the whole signal / packets.rrd / dot11.device sub-objects rather
    # than cherry-picking fields inside them: some Kismet versions don't
    # summarize nested fields (signal history RRD, advertised/probed ssid
    # maps, associated_client_map) correctly when they're asked for as
    # individual "container/subfield" paths, and silently drop them.
    # Requesting the container whole-sale matches a full (unfiltered) device
    # dump — and --db — and the same extract() walker reads either shape.
    "kismet.device.base.signal",
    "kismet.device.base.packets.rrd",
    "dot11.device",
]

ROLE_BY_TYPE = {
    "Wi-Fi AP": "ap",
    "Wi-Fi Ad-Hoc": "adhoc",
    "Wi-Fi Bridged": "bridged",
    "Wi-Fi Client": "client",
    "Wi-Fi Device": "device",
    "Wi-Fi WDS": "ap",
    "Wi-Fi WDS AP": "ap",
}


def extract(node, path):
    """Walk a slash-separated Kismet field path over a nested dict."""
    cur = node
    for part in path.split("/"):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _ssid_list(blob):
    """advertised/probed ssid maps are either a vector of objects (modern) or a
    map keyed by a hash (legacy). Return the list of SSID objects either way."""
    if blob is None:
        return []
    if isinstance(blob, list):
        return blob
    if isinstance(blob, dict):
        return list(blob.values())
    return []


def _clean_ssid(obj, key):
    if not isinstance(obj, dict):
        return None
    s = obj.get(key)
    if s is None:
        # some records nest under different exact key spellings
        for k, v in obj.items():
            if k.endswith(".ssid"):
                s = v
                break
    if s is None:
        return None
    s = str(s).strip()
    return s or None


def _band(freq):
    """Wi-Fi band label from a base frequency in kHz (e.g. 2462000 -> '2.4')."""
    try:
        mhz = int(freq) / 1000.0
    except (TypeError, ValueError):
        return ""
    if 2400 <= mhz < 2500:
        return "2.4"
    if 4900 <= mhz < 5895:
        return "5"
    if 5895 <= mhz < 7125:
        return "6"
    if 900 <= mhz < 1000:
        return "0.9"
    return ""


def _crypt_tier(crypt):
    """Collapse a Kismet crypt string to a coarse security tier for colouring.
    Returns one of: open, wep, wpa, wpa2, wpa3, other (or '' if unknown)."""
    c = (crypt or "").upper()
    if not c:
        return ""
    if "WPA3" in c or "SAE" in c:
        return "wpa3"
    if "WPA2" in c or "RSN" in c:
        return "wpa2"
    if "WPA" in c:
        return "wpa"
    if "WEP" in c:
        return "wep"
    if "NONE" in c or c.strip() in ("", "OPEN"):
        return "open"
    # Kismet reports open networks with an empty/whitespace crypt string; a
    # non-empty value we don't recognise is some other cipher.
    return "other"


def _signal_history(dev):
    """The signal RRD's per-minute vector, as a plain list (may be sparse)."""
    mv = extract(dev, "kismet.device.base.signal/"
                      "kismet.common.signal.signal_rrd/"
                      "kismet.common.rrd.minute_vec")
    if isinstance(mv, list):
        return [int(x) if isinstance(x, (int, float)) else 0 for x in mv]
    return []


def _packet_history(dev):
    """The packet-rate RRD's per-minute vector (packets per second over the last
    minute) — drives the activity glow, link flow, and packet-rate sparkline."""
    mv = extract(dev, "kismet.device.base.packets.rrd/"
                      "kismet.common.rrd.minute_vec")
    if isinstance(mv, list):
        return [int(x) if isinstance(x, (int, float)) and x > 0 else 0 for x in mv]
    return []


def normalize(dev):
    """Reduce a full/simplified Kismet device object to a flat record."""
    type_raw = extract(dev, "kismet.device.base.type") or ""
    if not type_raw.startswith("Wi-Fi"):
        # Non-802.11 phy (RTL433, BTLE, ...). Skip for a clean association graph.
        return None

    key = extract(dev, "kismet.device.base.key")
    mac = extract(dev, "kismet.device.base.macaddr")
    if not key and not mac:
        return None
    key = key or mac

    name = (extract(dev, "kismet.device.base.commonname")
            or extract(dev, "kismet.device.base.name") or "")

    # advertised SSIDs (APs). Also pull crypto/metadata off the primary record.
    ssids = []
    ssid_rec = None
    for o in _ssid_list(extract(dev, "dot11.device/dot11.device.advertised_ssid_map")):
        if ssid_rec is None and isinstance(o, dict):
            ssid_rec = o
        s = _clean_ssid(o, "dot11.advertisedssid.ssid")
        if s:
            ssids.append(s)
    ssid_rec = ssid_rec or {}

    # encryption: prefer the top-level crypt string, fall back to the ssid record
    crypt = (extract(dev, "kismet.device.base.crypt")
             or ssid_rec.get("dot11.advertisedssid.crypt_string") or "")
    crypt = str(crypt).strip()
    wps = bool(ssid_rec.get("dot11.advertisedssid.wps_state"))
    country = ssid_rec.get("dot11.advertisedssid.dot11d_country") or ""
    ht_mode = ssid_rec.get("dot11.advertisedssid.ht_mode") or ""
    txpower = ssid_rec.get("dot11.advertisedssid.advertised_txpower")
    if txpower in (None, 0):
        txpower = extract(dev, "dot11.device/dot11.device.max_tx_power")

    # probed SSIDs (clients looking for networks)
    probes = []
    for o in _ssid_list(extract(dev, "dot11.device/dot11.device.probed_ssid_map")):
        s = _clean_ssid(o, "dot11.probedssid.ssid")
        if s:
            probes.append(s)

    # associated clients (on APs): map of client-mac -> device-key, or a vector
    assoc = []
    acm = extract(dev, "dot11.device/dot11.device.associated_client_map")
    if isinstance(acm, dict):
        assoc = list(acm.keys())        # keys are client MACs
    elif isinstance(acm, list):
        assoc = [str(x) for x in acm]

    last_bssid = extract(dev, "dot11.device/dot11.device.last_bssid")
    if last_bssid in (None, "", "00:00:00:00:00:00"):
        last_bssid = None

    return {
        "key": key,
        "mac": mac or key,
        "type_raw": type_raw,
        "role": ROLE_BY_TYPE.get(type_raw, "device"),
        "name": name,
        "manuf": extract(dev, "kismet.device.base.manuf") or "",
        "channel": extract(dev, "kismet.device.base.channel") or "",
        "freq": extract(dev, "kismet.device.base.frequency") or 0,
        "packets": int(extract(dev, "kismet.device.base.packets.total") or 0),
        "first": int(extract(dev, "kismet.device.base.first_time") or 0),
        "last": int(extract(dev, "kismet.device.base.last_time") or 0),
        "sig_last": extract(dev, "kismet.device.base.signal/kismet.common.signal.last_signal"),
        "sig_max": extract(dev, "kismet.device.base.signal/kismet.common.signal.max_signal"),
        "sig_min": extract(dev, "kismet.device.base.signal/kismet.common.signal.min_signal"),
        "sig_hist": _signal_history(dev),
        "pkt_hist": _packet_history(dev),
        "datasize": int(extract(dev, "kismet.device.base.datasize") or 0),
        "band": _band(extract(dev, "kismet.device.base.frequency")),
        "crypt": crypt,
        "crypt_tier": _crypt_tier(crypt),
        "wps": wps,
        "country": str(country).strip(),
        "ht_mode": str(ht_mode).strip(),
        "txpower": txpower if isinstance(txpower, (int, float)) else None,
        "n_assoc": int(extract(dev, "dot11.device/dot11.device.num_associated_clients") or 0),
        "n_probed": int(extract(dev, "dot11.device/dot11.device.num_probed_ssids") or 0),
        "ssids": ssids,
        "probes": probes,
        "assoc": assoc,
        "last_bssid": last_bssid,
    }


# ---------------------------------------------------------------------------
# Source: Kismet log database (.kismetdb / SQLite)
# ---------------------------------------------------------------------------
def load_from_db(path):
    if not os.path.exists(path):
        sys.exit(f"error: database not found: {path}")
    con = sqlite3.connect(path)
    con.text_factory = bytes
    try:
        cur = con.execute("SELECT device FROM devices")
    except sqlite3.OperationalError as e:
        sys.exit(f"error: {path} does not look like a kismetdb (no 'devices' table): {e}")

    out = []
    for (blob,) in cur:
        if blob is None:
            continue
        if isinstance(blob, str):
            raw = blob.encode("utf-8", "replace")
        else:
            raw = blob
        # device JSON is normally plain text; tolerate gzip just in case
        if raw[:2] == b"\x1f\x8b":
            try:
                raw = gzip.decompress(raw)
            except OSError:
                pass
        try:
            dev = json.loads(raw.decode("utf-8", "replace"))
        except json.JSONDecodeError:
            continue
        rec = normalize(dev)
        if rec:
            out.append(rec)
    con.close()
    return out


# ---------------------------------------------------------------------------
# Source: live Kismet REST API
# ---------------------------------------------------------------------------
def _api_call(base, endpoint, user, password, apikey, payload=None, fatal=True):
    """GET/POST a Kismet endpoint and return decoded JSON. On error, exit (fatal)
    or return None (fatal=False) — the latter for optional data like alerts."""
    url = base.rstrip("/") + endpoint
    if apikey:
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}KISMET={urlparse.quote(apikey)}"
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if user is not None:
        tok = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
        headers["Authorization"] = "Basic " + tok
    req = urlrequest.Request(url, data=data, headers=headers,
                             method="POST" if data else "GET")
    try:
        with urlrequest.urlopen(req, timeout=30) as resp:
            body = resp.read()
    except urlerror.HTTPError as e:
        if not fatal:
            return None
        sys.exit(f"error: Kismet API {e.code} on {endpoint} "
                 f"({'auth failed?' if e.code in (401, 403) else e.reason})")
    except urlerror.URLError as e:
        if not fatal:
            return None
        sys.exit(f"error: cannot reach Kismet at {base}: {e.reason}")
    try:
        return json.loads(body.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        if not fatal:
            return None
        raise


def load_from_api(base, user, password, apikey, active_since):
    if active_since:
        endpoint = f"/devices/views/all/last-time/-{int(active_since)}/devices.json"
    else:
        endpoint = "/devices/views/all/devices.json"
    devices = _api_call(base, endpoint, user, password, apikey,
                        payload={"fields": API_FIELDS})
    if not isinstance(devices, list):
        sys.exit("error: unexpected API response (expected a device array)")
    out = []
    for dev in devices:
        rec = normalize(dev)
        if rec:
            out.append(rec)
    return out


# ---------------------------------------------------------------------------
# Alerts (Kismet's IDS/anomaly events: deauth floods, spoofing, ...)
# ---------------------------------------------------------------------------
def _norm_mac(m):
    m = (str(m).strip() if m is not None else "")
    return None if m in ("", "00:00:00:00:00:00") else m


def normalize_alert(a):
    """Flatten a Kismet alert record (API object or DB json blob) to a flat dict.
    Collects every MAC the alert references so it can be tied to a device node."""
    if not isinstance(a, dict):
        return None
    header = (a.get("kismet.alert.header") or a.get("header") or "").strip()
    text = (a.get("kismet.alert.text") or a.get("text") or "").strip()
    ts = (a.get("kismet.alert.timestamp") or a.get("ts_sec") or 0)
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        ts = 0
    sev = a.get("kismet.alert.severity")
    try:
        sev = int(sev) if sev is not None else 0
    except (TypeError, ValueError):
        sev = 0
    chan = a.get("kismet.alert.channel") or ""

    macs = []
    for k in ("kismet.alert.transmitter_mac", "kismet.alert.source_mac",
              "kismet.alert.dest_mac", "kismet.alert.other_mac", "devmac"):
        mac = _norm_mac(a.get(k))
        if mac and mac not in macs:
            macs.append(mac)
    # be tolerant of unknown key spellings that still name a MAC
    for k, v in a.items():
        if isinstance(k, str) and k.endswith("_mac"):
            mac = _norm_mac(v)
            if mac and mac not in macs:
                macs.append(mac)

    if not header and not text:
        return None
    return {"header": header or "ALERT", "text": text, "ts": int(ts),
            "sev": sev, "channel": str(chan), "macs": macs}


def load_alerts_from_db(path):
    """Read the kismetdb 'alerts' table. Each row has header/devmac/ts_sec and a
    json blob with the full alert detail."""
    out = []
    con = sqlite3.connect(path)
    con.text_factory = bytes
    try:
        cur = con.execute("SELECT ts_sec, devmac, header, json FROM alerts")
    except sqlite3.OperationalError:
        con.close()
        return out
    for ts_sec, devmac, header, blob in cur:
        a = {}
        if blob is not None:
            raw = blob if isinstance(blob, bytes) else str(blob).encode()
            if raw[:2] == b"\x1f\x8b":
                try:
                    raw = gzip.decompress(raw)
                except OSError:
                    pass
            try:
                a = json.loads(raw.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                a = {}
        # backfill from the dedicated columns if the blob lacked them
        a.setdefault("ts_sec", ts_sec)
        if header is not None:
            a.setdefault("header", header.decode() if isinstance(header, bytes) else header)
        if devmac is not None:
            a.setdefault("devmac", devmac.decode() if isinstance(devmac, bytes) else devmac)
        rec = normalize_alert(a)
        if rec:
            out.append(rec)
    con.close()
    return out


def load_alerts_from_api(base, user, password, apikey, active_since):
    """Fetch buffered alerts. Endpoint spelling varies between Kismet versions,
    so try the known ones and take the first that returns a list. Alerts are
    optional — a missing endpoint must not abort the run."""
    window = int(active_since) if active_since else 0
    endpoints = []
    if window:
        endpoints.append(f"/alerts/last-time/-{window}/alerts.json")
    endpoints += ["/alerts/last-time/0/alerts.json", "/alerts/all_alerts.json"]
    for ep in endpoints:
        res = _api_call(base, ep, user, password, apikey, fatal=False)
        if isinstance(res, dict):
            # some versions wrap the vector in a container
            res = res.get("kismet.alert.vector") or res.get("alerts") or None
        if isinstance(res, list):
            out = []
            for a in res:
                rec = normalize_alert(a)
                if rec:
                    out.append(rec)
            return out
    return []


# ---------------------------------------------------------------------------
# Build nodes + links
# ---------------------------------------------------------------------------
def build_graph(devices, include_ssids=True, link_radios=True, radio_prefix=5,
                alerts=None):
    by_key = {d["key"]: d for d in devices}
    mac_to_key = {}
    for d in devices:
        if d["mac"]:
            mac_to_key[d["mac"].lower()] = d["key"]

    nodes = {}
    for d in devices:
        label = d["name"]
        if d["role"] == "ap" and d["ssids"]:
            label = d["ssids"][0]
        if not label:
            label = d["mac"]
        nodes[d["key"]] = {
            "id": d["key"], "mac": d["mac"], "role": d["role"],
            "type": d["type_raw"], "name": d["name"], "label": label,
            "manuf": d["manuf"], "channel": str(d["channel"]),
            "freq": d["freq"], "band": d["band"], "packets": d["packets"],
            "datasize": d["datasize"],
            "first": d["first"], "last": d["last"],
            "sig": d["sig_last"] if d["sig_last"] not in (0, None) else d["sig_max"],
            "sig_min": d["sig_min"], "sig_max": d["sig_max"],
            "sig_hist": d["sig_hist"], "pkt_hist": d["pkt_hist"],
            "crypt": d["crypt"], "crypt_tier": d["crypt_tier"], "wps": d["wps"],
            "country": d["country"], "ht_mode": d["ht_mode"], "txpower": d["txpower"],
            "n_assoc": d["n_assoc"], "n_probed": d["n_probed"],
            "ssids": d["ssids"], "probes": d["probes"], "seen": True,
        }

    links = {}

    def add_link(a, b, rel):
        if a == b:
            return
        k = (a, b, rel) if a < b else (b, a, rel)
        links[k] = {"source": k[0], "target": k[1], "rel": rel}

    def ensure_phantom(mac):
        """A client referenced by an AP but never captured on its own."""
        key = mac_to_key.get(mac.lower())
        if key:
            return key
        pk = "phantom:" + mac
        if pk not in nodes:
            nodes[pk] = {
                "id": pk, "mac": mac, "role": "client", "type": "Wi-Fi Client",
                "name": "", "label": mac, "manuf": "", "channel": "", "freq": 0,
                "band": "", "packets": 0, "datasize": 0, "first": 0, "last": 0,
                "sig": None, "sig_min": None, "sig_max": None, "sig_hist": [],
                "pkt_hist": [],
                "crypt": "", "crypt_tier": "", "wps": False, "country": "",
                "ht_mode": "", "txpower": None, "n_assoc": 0, "n_probed": 0,
                "ssids": [], "probes": [], "seen": False,
            }
            mac_to_key[mac.lower()] = pk
        return pk

    # AP -> associated clients
    for d in devices:
        if d["assoc"]:
            for cmac in d["assoc"]:
                if not cmac:
                    continue
                add_link(d["key"], ensure_phantom(cmac), "assoc")
        # client -> its last BSSID (the AP it joined)
        if d["last_bssid"]:
            ap_key = mac_to_key.get(d["last_bssid"].lower())
            if ap_key:
                add_link(d["key"], ap_key, "assoc")

    # Optional SSID network layer
    if include_ssids:
        def ssid_node(name):
            sid = "ssid:" + name
            if sid not in nodes:
                nodes[sid] = {
                    "id": sid, "mac": "", "role": "ssid", "type": "SSID",
                    "name": name, "label": name, "manuf": "", "channel": "",
                    "freq": 0, "band": "", "packets": 0, "datasize": 0,
                    "first": 0, "last": 0, "sig": None, "sig_min": None,
                    "sig_max": None, "sig_hist": [], "pkt_hist": [], "crypt": "",
                    "crypt_tier": "", "wps": False, "country": "", "ht_mode": "",
                    "txpower": None, "n_assoc": 0, "n_probed": 0,
                    "ssids": [], "probes": [], "seen": True,
                }
            return sid
        for d in devices:
            for s in d["ssids"]:
                sid = ssid_node(s)
                add_link(d["key"], sid, "advertise")
                # An SSID network inherits the security of the AP advertising it,
                # so the network node can be coloured by encryption too.
                if d["crypt_tier"] and not nodes[sid]["crypt_tier"]:
                    nodes[sid]["crypt"] = d["crypt"]
                    nodes[sid]["crypt_tier"] = d["crypt_tier"]
                    nodes[sid]["wps"] = d["wps"]
            for s in d["probes"]:
                add_link(d["key"], ssid_node(s), "probe")

    # Radio siblings: BSSIDs of one physical AP. A multi-SSID AP gives each
    # SSID its own BSSID derived from the radio's base MAC (only the low octet
    # changes), so it shows up as several AP nodes. Link nodes that share the
    # high-order MAC prefix AND sit on the same channel (one radio => co-channel,
    # which rules out same-vendor coincidences).
    if link_radios:
        def mac_prefix(mac, n):
            parts = (mac or "").upper().split(":")
            return ":".join(parts[:n]) if len(parts) >= n else (mac or "").upper()

        groups = {}
        for n in nodes.values():
            if n["role"] == "ap" and n["mac"]:
                groups.setdefault(mac_prefix(n["mac"], radio_prefix), []).append(n)

        for members in groups.values():
            if len(members) < 2:
                continue
            members.sort(key=lambda x: x["mac"])   # anchor = base/reference BSSID
            anchor = members[0]
            ach = str(anchor["channel"] or "")
            for m in members[1:]:
                mch = str(m["channel"] or "")
                if ach and mch and ach != mch:
                    continue                       # different channel => different radio
                add_link(anchor["id"], m["id"], "radio")

    # degree (drives node size)
    for n in nodes.values():
        n["degree"] = 0
        n["alerts"] = 0
    for l in links.values():
        nodes[l["source"]]["degree"] += 1
        nodes[l["target"]]["degree"] += 1

    # Alerts overlay: tie each alert to the device node(s) it names (by any of
    # its MACs). Alerts naming no captured device stay in the feed as "unlinked".
    out_alerts = []
    for a in (alerts or []):
        nid = None
        for mac in a["macs"]:
            k = mac_to_key.get(mac.lower())
            if k:
                nid = k
                nodes[k]["alerts"] += 1
                break
        out_alerts.append({
            "id": nid, "header": a["header"], "text": a["text"],
            "ts": a["ts"], "sev": a["sev"], "channel": a["channel"],
            "mac": a["macs"][0] if a["macs"] else "",
        })
    out_alerts.sort(key=lambda x: x["ts"], reverse=True)

    return {"nodes": list(nodes.values()), "links": list(links.values()),
            "alerts": out_alerts}


TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.9.0/d3.min.js"></script>
<style>
  :root{
    --bg0:#0A111E; --bg1:#0E1A2E; --bg2:#12233c;
    --panel:rgba(14,25,44,.74); --panel-solid:#0f1c33;
    --line:rgba(120,150,200,.16); --line-strong:rgba(140,170,220,.34);
    --ink:#E7EEF9; --muted:#8A9AB8; --faint:#5C6E90;
    --ap:#F5A524; --client:#34D6CE; --bridged:#7C9CF5; --device:#9AA7C2;
    --adhoc:#C77DFF; --ssid:#FF5C8A;
    --mono:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace;
    --sans:"Inter",system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{height:100%}
  body{
    margin:0;font-family:var(--sans);color:var(--ink);overflow:hidden;
    background:
      radial-gradient(1200px 900px at 62% 42%, #14243f 0%, var(--bg1) 42%, var(--bg0) 100%);
  }
  svg#scope{position:fixed;inset:0;width:100vw;height:100vh;display:block;cursor:grab}
  svg#scope:active{cursor:grabbing}

  /* ---- scope backdrop rings ---- */
  .ring{fill:none;stroke:var(--line);stroke-width:1}
  .ring.tick{stroke:rgba(120,150,200,.08)}
  .crosshair{stroke:rgba(120,150,200,.10);stroke-width:1}

  /* ---- links ---- */
  .link{stroke:var(--line-strong);stroke-width:1.1;fill:none}
  .link.advertise{stroke:rgba(245,165,36,.26)}
  .link.probe{stroke:rgba(255,92,138,.30);stroke-dasharray:3 4}
  .link.radio{stroke:var(--ap);stroke-width:2.4;opacity:.55;
    filter:drop-shadow(0 0 3px rgba(245,165,36,.5))}
  .link.dim{stroke:rgba(120,150,200,.05);filter:none}
  .link.hot{stroke:rgba(220,235,255,.85);stroke-width:1.8}
  /* traffic flow: dashes stream along links whose endpoints are active */
  .link.flow{stroke:rgba(120,214,206,.65);stroke-dasharray:2.5 6;
    animation:flow .7s linear infinite}
  @keyframes flow{to{stroke-dashoffset:-8.5}}

  /* ---- nodes ---- */
  .node{cursor:pointer}
  .node .core{stroke:rgba(6,12,22,.85);stroke-width:1.2;transition:filter .15s}
  .node.phantom .core{fill:transparent!important;stroke-dasharray:2 3;stroke:var(--client);opacity:.7}
  /* Rotate/scale these around their OWN centre. Without transform-box:fill-box,
     an SVG element's transform-origin defaults to the whole SVG's view-box, so
     "center" is the middle of the screen — making the ring orbit the scope
     instead of spinning in place. */
  .node .gauge,.node .warn,.node .busy,.node .flashring{transform-box:fill-box}
  .node .gauge{fill:none;stroke-linecap:round;opacity:.9;transform:rotate(-90deg);transform-origin:center}
  .node .label{
    font-family:var(--mono);font-size:10.5px;fill:var(--muted);
    paint-order:stroke;stroke:rgba(8,14,26,.9);stroke-width:3px;
    pointer-events:none;opacity:0;transition:opacity .15s}
  .node.showlabel .label,.node.hot .label{opacity:1;fill:var(--ink)}
  .node.dim{opacity:.18}
  .node.hot .core{filter:drop-shadow(0 0 7px currentColor)}
  .node.match .core{stroke:#fff;stroke-width:2.2}
  .role-ap .core{fill:var(--ap);color:var(--ap)}
  .role-client .core{fill:var(--client);color:var(--client)}
  .role-bridged .core{fill:var(--bridged);color:var(--bridged)}
  .role-device .core{fill:var(--device);color:var(--device)}
  .role-adhoc .core{fill:var(--adhoc);color:var(--adhoc)}
  .role-ssid .core{fill:var(--ssid);color:var(--ssid)}
  /* ---- security warning ring (open / WEP / WPS networks) ---- */
  /* The spin is driven by the Web Animations API (see drawNode) so its speed can
     be changed live via playbackRate — a compositor-friendly change that a CSS
     animation-duration tweak is not. transform-origin/-box keep it spinning in
     place (see the shared fill-box rule above). */
  .node .warn{fill:none;stroke-width:1.6;opacity:.9;stroke-dasharray:2 3;
    transform-origin:center}
  /* ---- alert marker (device named in a Kismet IDS alert) ---- */
  .node .alertring{fill:none;stroke:#FF3B57;stroke-width:2.2;
    filter:drop-shadow(0 0 5px rgba(255,59,87,.85));
    animation:alertpulse 1.3s ease-in-out infinite}
  @keyframes alertpulse{0%,100%{opacity:.3}50%{opacity:1}}
  /* ---- activity: busy halo (traffic volume) + live ping (new packets) ---- */
  .node .busy{pointer-events:none;transform-origin:center;
    animation:busypulse 1.9s ease-in-out infinite}
  @keyframes busypulse{0%,100%{transform:scale(.9)}50%{transform:scale(1.14)}}
  .node .flashring{fill:none;stroke:#EAF2FF;stroke-width:2;pointer-events:none;
    transform-origin:center;animation:flashring .85s ease-out forwards}
  @keyframes flashring{0%{transform:scale(1);opacity:.85}100%{transform:scale(2.7);opacity:0}}

  /* ---- chrome / panels ---- */
  .panel{
    position:fixed;background:var(--panel);border:1px solid var(--line);
    border-radius:12px;backdrop-filter:blur(9px);-webkit-backdrop-filter:blur(9px);
    box-shadow:0 12px 40px rgba(0,0,0,.42)}
  .eyebrow{font-family:var(--mono);font-size:10px;letter-spacing:.22em;
    text-transform:uppercase;color:var(--faint)}

  #brand{top:18px;left:18px;padding:14px 16px 12px;max-width:290px}
  #brand h1{margin:2px 0 0;font-family:var(--mono);font-size:15px;font-weight:600;
    letter-spacing:.18em;text-transform:uppercase}
  #brand .src{margin-top:7px;font-family:var(--mono);font-size:11px;color:var(--muted);
    word-break:break-all;display:flex;align-items:center;gap:7px}
  .pulse{width:7px;height:7px;border-radius:50%;background:var(--client);
    box-shadow:0 0 0 0 rgba(52,214,206,.6);animation:pulse 2.4s infinite}
  .pulse.err{background:#FF5C6C;box-shadow:none;animation:none}
  @keyframes pulse{0%{box-shadow:0 0 0 0 rgba(52,214,206,.5)}
    70%{box-shadow:0 0 0 7px rgba(52,214,206,0)}100%{box-shadow:0 0 0 0 rgba(52,214,206,0)}}
  #liveStatus{margin-top:5px;font-family:var(--mono);font-size:10.5px;color:var(--muted)}
  #liveStatus.stale{color:#FF5C6C}

  #controls{top:18px;right:18px;padding:12px;display:flex;flex-direction:column;gap:10px;width:236px}
  #search{width:100%;background:rgba(8,15,28,.8);border:1px solid var(--line-strong);
    border-radius:8px;color:var(--ink);font-family:var(--mono);font-size:12px;
    padding:9px 11px;outline:none}
  #search:focus{border-color:var(--client);box-shadow:0 0 0 3px rgba(52,214,206,.15)}
  #search::placeholder{color:var(--faint)}
  .ctl-row{display:flex;gap:8px}
  .btn{flex:1;background:rgba(20,32,54,.7);border:1px solid var(--line-strong);
    color:var(--muted);font-family:var(--mono);font-size:10.5px;letter-spacing:.08em;
    text-transform:uppercase;padding:8px 6px;border-radius:8px;cursor:pointer;transition:.15s}
  .btn:hover{color:var(--ink);border-color:var(--client)}
  .slider{display:flex;flex-direction:column;gap:3px}
  .slider label{font-family:var(--mono);font-size:10px;color:var(--faint);
    display:flex;justify-content:space-between}
  input[type=range]{width:100%;accent-color:var(--client);height:3px}
  #legend{left:18px;bottom:18px;padding:11px 13px;display:flex;flex-direction:column;gap:1px;
    max-height:calc(100vh - 36px);overflow-y:auto;overflow-x:hidden}
  #legend .eyebrow{margin-bottom:5px}
  #legend .leg-h{margin-top:9px}
  .leg-top{display:flex;align-items:center;justify-content:space-between;gap:16px;
    cursor:pointer;user-select:none}
  .leg-top .eyebrow{margin-bottom:0}
  .leg-caret{font-family:var(--mono);font-size:10px;letter-spacing:.1em;color:var(--faint);
    white-space:nowrap;transition:.12s}
  .leg-top:hover .leg-caret{color:var(--ink)}
  #legend-layers{display:flex;flex-direction:column;gap:1px}
  .chip{display:flex;align-items:center;gap:9px;padding:4px 7px;border-radius:7px;
    cursor:pointer;font-size:12px;color:var(--muted);user-select:none;transition:.12s}
  .chip:hover{background:rgba(120,150,200,.08);color:var(--ink)}
  .chip.off{opacity:.34}
  .chip .dot{width:10px;height:10px;border-radius:50%;flex:none}
  .chip .dot.d{border-radius:2px;transform:rotate(45deg)}
  .chip .n{margin-left:auto;font-family:var(--mono);font-size:10.5px;color:var(--faint)}
  /* legend swatches for the visual layers */
  .chip .sw{width:20px;display:inline-flex;align-items:center;justify-content:center;flex:none}
  .chip .lbl2{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .sw-line{width:18px;height:2px;border-radius:2px;background:var(--c)}
  .sw-line.dash{height:0;background:none;border-top:2px dashed var(--c)}
  .sw-ring{width:12px;height:12px;border-radius:50%;border:2px solid var(--c);box-sizing:border-box}
  .sw-ring.dash{border-style:dashed}
  .sw-glow{width:13px;height:13px;border-radius:50%;
    background:radial-gradient(circle,var(--client) 0%,rgba(52,214,206,.15) 45%,rgba(52,214,206,0) 72%)}
  .sw-fade{width:16px;height:9px;border-radius:5px;
    background:linear-gradient(90deg,var(--client),rgba(52,214,206,.12))}
  /* layer on/off hiding (a "no-KEY" body class hides that layer's elements) */
  body.no-assoc .link.assoc{display:none}
  body.no-advertise .link.advertise{display:none}
  body.no-probe .link.probe{display:none}
  body.no-radio .link.radio{display:none}
  body.no-gauge .gauge{display:none}
  body.no-security .warn{display:none}
  body.no-alert .alertring{display:none}
  body.no-alert #alerts{display:none!important}
  body.no-glow .busy{display:none}
  body.no-ping .flashring{display:none}
  body.no-backdrop .ring,body.no-backdrop .crosshair{display:none}

  /* ---- alerts feed (top centre) ---- */
  #alerts{top:18px;left:50%;transform:translateX(-50%);padding:11px 13px 9px;
    width:340px;max-width:calc(100vw - 36px);border-color:rgba(255,59,87,.4)}
  #alerts .eyebrow{color:#FF8A96;margin-bottom:7px;display:flex;align-items:center;gap:7px}
  #alerts .adot{width:7px;height:7px;border-radius:50%;background:#FF3B57;
    box-shadow:0 0 0 0 rgba(255,59,87,.6);animation:alertpulse 1.3s ease-in-out infinite}
  .arow{display:flex;align-items:baseline;gap:9px;padding:5px 6px;border-radius:7px;
    cursor:pointer;transition:.12s}
  .arow:hover{background:rgba(255,59,87,.10)}
  .arow.unlinked{cursor:default}.arow.unlinked:hover{background:none}
  .arow .ah{font-family:var(--mono);font-size:11px;color:#FF9FA9;font-weight:600;
    white-space:nowrap}
  .arow .ad{font-family:var(--mono);font-size:11px;color:var(--muted);flex:1;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .arow .at{font-family:var(--mono);font-size:9.5px;color:var(--faint);white-space:nowrap}
  #alerts-list.expanded{max-height:min(52vh,420px);overflow-y:auto}
  #alerts .amore{font-family:var(--mono);font-size:10px;color:var(--muted);padding:6px 6px 2px;
    cursor:pointer;letter-spacing:.06em}
  #alerts .amore:hover{color:var(--ink)}
  body.has-selection #alerts{transform:translateX(calc(-50% - 176px));transition:transform .28s}

  /* ---- dossier alerts section ---- */
  .dalerts{padding:0 20px}
  .dalerts:empty{display:none}
  .dalerts .eyebrow{color:#FF8A96;padding:14px 0 8px}
  .dalerts .da{border-left:2px solid #FF3B57;padding:5px 0 5px 10px;margin-bottom:8px}
  .dalerts .da .h{font-family:var(--mono);font-size:11.5px;color:#FF9FA9;font-weight:600}
  .dalerts .da .x{font-family:var(--mono);font-size:11px;color:var(--muted);margin-top:2px;
    line-height:1.35;word-break:break-word}
  .dalerts .da .t{font-family:var(--mono);font-size:9.5px;color:var(--faint);margin-top:3px}

  #stats{right:18px;bottom:18px;padding:11px 15px;display:flex;gap:20px}
  #stats .stat{text-align:right}
  #stats .stat.alert .v{color:#FF6B78}
  #stats .v{font-family:var(--mono);font-size:19px;font-weight:600;line-height:1}
  #stats .k{font-family:var(--mono);font-size:9px;letter-spacing:.16em;
    text-transform:uppercase;color:var(--faint);margin-top:4px}

  /* ---- dossier ---- */
  #dossier{top:0;right:0;height:100vh;width:340px;transform:translateX(104%);
    transition:transform .28s cubic-bezier(.4,0,.2,1);border-radius:0;
    border-left:1px solid var(--line-strong);background:var(--panel);
    backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);
    display:flex;flex-direction:column;z-index:20}
  body.has-selection #dossier{transform:translateX(0)}
  body.has-selection #controls{transform:translateX(-352px);transition:transform .28s}
  #dossier header{padding:20px 20px 16px;border-bottom:1px solid var(--line)}
  #dossier .role-tag{font-family:var(--mono);font-size:10px;letter-spacing:.16em;
    text-transform:uppercase;display:inline-flex;align-items:center;gap:7px}
  #dossier h2{margin:10px 0 2px;font-family:var(--mono);font-size:17px;font-weight:600;
    word-break:break-all;line-height:1.25}
  #dossier .mac{font-family:var(--mono);font-size:12px;color:var(--muted)}
  #dclose{position:absolute;top:16px;right:16px;width:28px;height:28px;border-radius:7px;
    border:1px solid var(--line-strong);background:transparent;color:var(--muted);
    cursor:pointer;font-size:15px;line-height:1}
  #dclose:hover{color:var(--ink);border-color:var(--client)}
  .facts{padding:16px 20px;display:grid;grid-template-columns:1fr 1fr;gap:12px 16px;
    border-bottom:1px solid var(--line)}
  .fact.wide{grid-column:1 / -1}
  .fact .k{font-family:var(--mono);font-size:9px;letter-spacing:.14em;
    text-transform:uppercase;color:var(--faint)}
  .fact .v{font-family:var(--mono);font-size:13px;color:var(--ink);margin-top:3px;word-break:break-all}
  .fact .v.risk{color:#FF5C6C}
  .fact .v .badge{display:inline-block;font-size:9px;padding:1px 5px;border-radius:5px;
    margin-left:6px;letter-spacing:.08em;vertical-align:middle;
    background:rgba(255,92,108,.16);color:#FF8A96}
  /* signal history sparkline */
  .spark{grid-column:1 / -1;padding-top:2px}
  .spark svg{display:block;width:100%;height:38px;overflow:visible}
  .spark .sline{fill:none;stroke:var(--client);stroke-width:1.5}
  .spark .sdot{fill:var(--client)}
  .spark .sarea{opacity:.14}
  .conn{flex:1;overflow-y:auto;padding:14px 14px 24px}
  .conn .eyebrow{padding:0 6px 8px}
  .conn a{display:flex;align-items:center;gap:10px;padding:9px 10px;border-radius:8px;
    text-decoration:none;color:var(--muted);cursor:pointer;transition:.12s}
  .conn a:hover{background:rgba(120,150,200,.09);color:var(--ink)}
  .conn a .dot{width:9px;height:9px;border-radius:50%;flex:none}
  .conn a .lbl{font-family:var(--mono);font-size:12px;white-space:nowrap;
    overflow:hidden;text-overflow:ellipsis}
  .conn a .rel{margin-left:auto;font-family:var(--mono);font-size:9px;color:var(--faint);
    text-transform:uppercase;letter-spacing:.1em;flex:none}

  /* ---- tooltip ---- */
  #tip{position:fixed;pointer-events:none;z-index:40;opacity:0;transition:opacity .1s;
    background:var(--panel-solid);border:1px solid var(--line-strong);border-radius:9px;
    padding:9px 12px;font-family:var(--mono);font-size:11.5px;max-width:260px;
    box-shadow:0 10px 30px rgba(0,0,0,.5)}
  #tip .t-lbl{color:var(--ink);font-size:12.5px;margin-bottom:3px;word-break:break-all}
  #tip .t-row{color:var(--muted)}
  #tip .t-row b{color:var(--ink);font-weight:600}

  #empty{position:fixed;inset:0;display:none;place-items:center;text-align:center}
  #empty div{font-family:var(--mono);color:var(--muted)}

  @media (max-width:720px){
    #controls{width:200px} #dossier{width:100vw}
    body.has-selection #controls{transform:translateX(-100vw)}
    #brand{max-width:200px}
  }
  @media (prefers-reduced-motion:reduce){
    *{transition:none!important;animation:none!important}
  }
</style>
</head>
<body>
<svg id="scope"></svg>

<div id="brand" class="panel">
  <div class="eyebrow">Kismet · Relation Scope</div>
  <h1>__TITLE__</h1>
  <div class="src"><span class="pulse" id="pulse"></span><span>__SOURCE__</span></div>
  <div id="liveStatus" style="display:none"></div>
</div>

<div id="controls" class="panel">
  <input id="search" type="search" placeholder="search mac · name · ssid · vendor" autocomplete="off">
  <div class="ctl-row">
    <button class="btn" id="fit">Reset view</button>
    <button class="btn" id="freeze">Freeze</button>
  </div>
  <div class="slider">
    <label>Spread <span id="chargeV"></span></label>
    <input type="range" id="charge" min="60" max="900" value="320">
  </div>
  <div class="slider">
    <label>Link length <span id="distV"></span></label>
    <input type="range" id="dist" min="20" max="220" value="74">
  </div>
  <div class="slider">
    <label>Rotation <span id="spinV"></span></label>
    <input type="range" id="spin" min="0" max="100" value="0">
  </div>
</div>

<div id="legend" class="panel"></div>

<div id="alerts" class="panel" style="display:none">
  <div class="eyebrow" id="alerts-head">Alerts</div>
  <div id="alerts-list"></div>
</div>

<div id="stats" class="panel"></div>

<div id="dossier" class="panel">
  <button id="dclose" aria-label="Close">✕</button>
  <header>
    <span class="role-tag" id="d-role"></span>
    <h2 id="d-title"></h2>
    <div class="mac" id="d-mac"></div>
  </header>
  <div class="facts" id="d-facts"></div>
  <div class="dalerts" id="d-alerts"></div>
  <div class="conn"><div class="eyebrow">Connected contacts</div><div id="d-conn"></div></div>
</div>

<div id="tip"></div>
<div id="empty"><div>No devices in this capture.</div></div>

<script>
const GRAPH = /*__DATA__*/;
const LIVE = __LIVE__;
const POLL_MS = __POLL_MS__;

const ROLE = {
  ap:{c:'#F5A524',name:'Access point'}, client:{c:'#34D6CE',name:'Client'},
  bridged:{c:'#7C9CF5',name:'Bridged / wired'}, device:{c:'#9AA7C2',name:'Unknown role'},
  adhoc:{c:'#C77DFF',name:'Ad-hoc'}, ssid:{c:'#FF5C8A',name:'SSID network'}
};
const ORDER = ['ap','client','bridged','adhoc','device','ssid'];

// encryption tier -> label + colour. open / WEP / WPS are treated as risks.
const CRYPT = {
  open:{name:'Open (no encryption)', c:'#FF5C6C', risk:true},
  wep :{name:'WEP (weak)',           c:'#FF9F45', risk:true},
  wpa :{name:'WPA (legacy)',         c:'#F5C518', risk:false},
  wpa2:{name:'WPA2',                 c:'#8AB0FF', risk:false},
  wpa3:{name:'WPA3',                 c:'#34D6CE', risk:false},
  other:{name:'Encrypted',           c:'#9AA7C2', risk:false}
};
// a node is a "risk" (gets a warning ring) if it's open/WEP or has WPS on
const nodeRisk = d => (CRYPT[d.crypt_tier] && CRYPT[d.crypt_tier].risk) || !!d.wps;
const riskColor = d => (d.crypt_tier==='open'||d.crypt_tier==='wep')
  ? CRYPT[d.crypt_tier].c : '#FF9F45';   // WPS-only -> amber

// signal (dBm) -> colour ramp for the gauge ring
const sigColor = d3.scaleLinear()
  .domain([-95,-75,-55,-40]).clamp(true)
  .range(['#2C5A8C','#34D6CE','#F5A524','#FF5C6C'])
  .interpolate(d3.interpolateRgb);
const sigFrac = s => Math.max(0,Math.min(1,(s+95)/55));

const svg = d3.select('#scope');
let W = window.innerWidth, H = window.innerHeight;
const root = svg.append('g');            // zoom target
const gBack = root.append('g');          // scope rings
const gLink = root.append('g');
const gNode = root.append('g');

// scope backdrop
function drawBack(){
  gBack.selectAll('*').remove();
  const cx=W/2, cy=H/2, maxR=Math.hypot(W,H)/2;
  for(let r=140;r<maxR;r+=140)
    gBack.append('circle').attr('class','ring tick').attr('cx',cx).attr('cy',cy).attr('r',r);
  gBack.append('line').attr('class','crosshair').attr('x1',cx).attr('y1',0).attr('x2',cx).attr('y2',H);
  gBack.append('line').attr('class','crosshair').attr('x1',0).attr('y1',cy).attr('x2',W).attr('y2',cy);
}
drawBack();

// ---- scales ----
const rScale = d3.scaleSqrt().range([4.5,17]);
function sizeNodes(nodes){
  const maxDeg = d3.max(nodes, d=>d.degree)||1;
  rScale.domain([0,maxDeg]);
  nodes.forEach(n=>{
    n.r = n.role==='ap' ? Math.max(8,rScale(n.degree))
        : n.role==='ssid' ? Math.max(6,rScale(n.degree)*.9)
        : rScale(n.degree);
  });
}

// ---- simulation ----
let baseDist = 74;
const linkDist = d => d.rel==='radio' ? 24
                    : (d.rel==='advertise'||d.rel==='probe') ? baseDist*0.85
                    : baseDist;
const linkStr  = d => d.rel==='radio' ? 1.0 : 0.5;

const sim = d3.forceSimulation([])
  .force('link', d3.forceLink([]).id(d=>d.id).distance(linkDist).strength(linkStr))
  .force('charge', d3.forceManyBody().strength(-320))
  .force('center', d3.forceCenter(W/2,H/2))
  .force('collide', d3.forceCollide(d=>d.r+4).strength(.85))
  .force('x', d3.forceX(W/2).strength(.02))
  .force('y', d3.forceY(H/2).strength(.02));

const drag = d3.drag()
  .on('start',(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
  .on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y;})
  .on('end',(e,d)=>{if(!e.active)sim.alphaTarget(0);if(!d.pinned){d.fx=null;d.fy=null;}});

let link = gLink.selectAll('line');
let node = gNode.selectAll('g.node');

function drawNode(g,d){
  g.selectAll('*').remove();
  // busy halo (behind everything): size + opacity scale with recent packet rate
  // (drawn whenever there's activity; the "Glow" layer toggle hides it via CSS)
  if(d.act>0){
    const f=Math.min(1, d.act/actMax);
    g.append('circle').attr('class','busy')
      .attr('r', d.r + 4 + 9*f).attr('fill', ROLE[d.role].c)
      .style('opacity', 0.10 + 0.32*f);
  }
  if(d.sig!=null && d.role!=='ssid'){
    const gr=d.r+3.5, c=2*Math.PI*gr;
    g.append('circle').attr('class','gauge').attr('r',gr)
      .attr('stroke',sigColor(d.sig)).attr('stroke-width',2.4)
      .attr('stroke-dasharray',c).attr('stroke-dashoffset',c*(1-sigFrac(d.sig)));
  }
  // security warning ring: open / WEP networks, or WPS enabled. Spun in place
  // via the Web Animations API (transform-box:fill-box keeps it centred).
  if(nodeRisk(d)){
    const wc=g.append('circle').attr('class','warn').attr('r',d.r+ (d.role==='ssid'?4:6.5))
      .attr('stroke',riskColor(d));
    wc.node().animate(
      [{transform:'rotate(0deg)'},{transform:'rotate(360deg)'}],
      {duration:9000, iterations:Infinity, easing:'linear'});
  }
  // alert ring: device named in one or more Kismet IDS alerts
  if(d.alerts>0){
    g.append('circle').attr('class','alertring').attr('r',d.r+ (d.role==='ssid'?7.5:10));
  }
  if(d.role==='ssid'){
    const s=d.r;
    g.append('path').attr('class','core')
      .attr('d',`M0,${-s} L${s},0 L0,${s} L${-s},0 Z`);
  }else{
    g.append('circle').attr('class','core').attr('r',d.r);
  }
  // live ping: one-shot ripple when this device just sent/received packets
  // (the "Ping" layer toggle hides it via CSS)
  if(d.justActive){
    g.append('circle').attr('class','flashring').attr('r',d.r);
  }
  g.append('text').attr('class','label').attr('dy','.32em').attr('x',d.r+5).text(d.label);
}

// ---- selection / neighbours (rebuilt on every apply) ----
const nodeById = new Map();
const adj = new Map();
let selected=null;

// ---- alerts (Kismet IDS events), grouped by the device node they name ----
const alertsById = new Map();
let allAlerts = [];
function rebuildAlerts(){
  alertsById.clear();
  allAlerts = (GRAPH.alerts||[]).slice();
  for(const a of allAlerts){
    if(a.id==null) continue;
    if(!alertsById.has(a.id)) alertsById.set(a.id,[]);
    alertsById.get(a.id).push(a);
  }
}

// ---- activity fade: contacts that have gone quiet dim toward FADE_MIN ----
// refTime is the newest last-seen across the graph (≈ "now" in live mode, or
// the capture's end for a static file), so age is measured relative to it.
const FADE_LIVE = 300;     // live: seconds of silence to reach full fade
const FADE_MIN = 0.3;      // opacity floor for long-quiet contacts
let refTime = 0;           // "now" reference for age (advances in live mode)
let graphMaxLast = 0;      // newest last-seen in the current graph
let fadeWindow = FADE_LIVE;// seconds; adaptive to capture span in static mode
let pollServerTime = 0, pollWall = 0;   // server clock anchor for live fade
// best estimate of the server's current unix time; 0 (=> no advance) unless live
function estimatedNow(){
  if(!pollServerTime) return 0;
  return pollServerTime + (Date.now()-pollWall)/1000;
}
function nodeOpacity(d){
  if(!d.seen) return 0.5;              // referenced-only (phantom) contacts
  if(!d.last) return 0.85;
  const age = refTime - d.last;
  if(age<=0) return 1;
  return Math.max(FADE_MIN, 1 - (age/fadeWindow)*(1-FADE_MIN));
}
function applyFade(){
  if(selected!==null) return;          // selection styling owns opacity then
  if(!layers.fade){ node.style('opacity', d=>d.seen?1:0.5); return; }
  node.style('opacity', d=>nodeOpacity(d));
}

// ---- activity: recent packet rate drives the busy halo + link flow ----
let firstApply = true;   // suppress "new device" ping storm on initial load
let actMax = 1;          // busiest recent packet rate, for scaling the glow
let flowThresh = 4;      // min recent rate for a link to animate its flow
// viewer on/off state for every toggleable visual layer (all on by default).
// The `no-KEY` body classes (assoc..backdrop) hide their elements via CSS;
// flow/fade/sigspark/pktspark are applied in JS.
const layers = {
  assoc:true, advertise:true, probe:true, radio:true, flow:true,
  gauge:true, fade:true, security:true, alert:true,
  glow:true, ping:true, sigspark:true, pktspark:true, backdrop:true,
};
function recentRate(h){
  if(!h||!h.length) return 0;
  let s=0; for(const v of h) if(v>0) s+=v;   // packets in the last minute
  return s;
}
function updateFlow(){
  // flow dashes on assoc links whose device(s) are notably active (if enabled)
  link.classed('flow', l=>{
    if(!layers.flow || l.rel!=='assoc') return false;
    const s=nodeById.get(l.source.id||l.source), t=nodeById.get(l.target.id||l.target);
    return (s&&s.act>=flowThresh)||(t&&t.act>=flowThresh);
  });
}
// keys whose layer is toggled purely by hiding elements via a `no-KEY` body class
const CSS_LAYERS = ['assoc','advertise','probe','radio','gauge','security',
                    'alert','glow','ping','backdrop'];
function applyLayers(){
  const cl=document.body.classList;
  CSS_LAYERS.forEach(k=>cl.toggle('no-'+k, !layers[k]));
  updateFlow();                                   // flow (JS)
  applyFade();                                    // fade (JS)
  if(selected!==null) fillDossier(nodeById.get(selected)); // signal/packet sparklines
}

// ---- merge + (re)draw a fresh graph snapshot into the running simulation ----
function apply(newGraph){
  const newIds = new Set(newGraph.nodes.map(n=>n.id));
  // Index existing nodes by MAC so a device keeps its place when its id changes
  // — e.g. an inferred "phantom" client that later gets directly captured swaps
  // its "phantom:MAC" id for a real Kismet key. Without this it would be pruned
  // and re-seeded at the centre, looking like a brand-new contact spawning.
  const macIndex = new Map();
  for(const n of nodeById.values()){
    if(n.mac) macIndex.set(n.mac.toLowerCase(), n);
  }
  newGraph.nodes.forEach(nd=>{
    const existing = nodeById.get(nd.id);
    if(existing){
      const prevPk = existing.packets||0;
      const {x,y,vx,vy,fx,fy} = existing;
      Object.assign(existing, nd, {x,y,vx,vy,fx,fy});
      // live ping: this device sent/received new packets since the last poll
      existing.justActive = nd.packets > prevPk;
    }else{
      const prior = nd.mac ? macIndex.get(nd.mac.toLowerCase()) : null;
      if(prior && !newIds.has(prior.id)){
        // same device under a new id (phantom<->real): carry its position over
        // and don't treat it as a fresh discovery.
        nd.x=prior.x; nd.y=prior.y; nd.vx=prior.vx; nd.vy=prior.vy;
        nd.fx=prior.fx; nd.fy=prior.fy; nd.pinned=prior.pinned;
        nd.justActive=false;
      }else{
        nd.x = W/2 + (Math.random()-0.5)*60;
        nd.y = H/2 + (Math.random()-0.5)*60;
        nd.justActive = !firstApply;   // a genuinely new contact pings once
      }
      nodeById.set(nd.id, nd);
    }
  });
  for(const id of Array.from(nodeById.keys())){
    if(!newIds.has(id)) nodeById.delete(id);
  }
  GRAPH.nodes = Array.from(nodeById.values());
  GRAPH.links = newGraph.links;
  GRAPH.links.forEach(l=>{ l.key = l.rel+'|'+l.source+'|'+l.target; });
  GRAPH.alerts = newGraph.alerts || [];
  rebuildAlerts();
  sizeNodes(GRAPH.nodes);
  // recent packet-rate activity (busy halo + link flow)
  GRAPH.nodes.forEach(n=>{ n.act = recentRate(n.pkt_hist); });
  actMax = d3.max(GRAPH.nodes, n=>n.act) || 1;
  // flow animation is reserved for notably-busy links so it stays a signal, not
  // noise; the halo still fades in gradually on any activity.
  flowThresh = Math.max(4, actMax*0.08);
  const lasts = GRAPH.nodes.map(n=>n.last).filter(x=>x>0);
  graphMaxLast = d3.max(lasts) || 0;
  const minLast = d3.min(lasts) || graphMaxLast;
  // live: fixed recency window. static: spread fade across the capture's own
  // timespan so a snapshot shades oldest->newest instead of washing out.
  fadeWindow = estimatedNow()>0 ? FADE_LIVE : Math.max(120, graphMaxLast-minLast);
  refTime = Math.max(graphMaxLast, estimatedNow());

  adj.clear();
  GRAPH.nodes.forEach(n=>adj.set(n.id,[]));
  GRAPH.links.forEach(l=>{
    adj.get(l.source).push({id:l.target,rel:l.rel});
    adj.get(l.target).push({id:l.source,rel:l.rel});
  });

  if(frozen){
    // keep the layout still: pin any newly-arrived node where it was seeded
    GRAPH.nodes.forEach(n=>{ if(n.fx==null){ n.fx=n.x; n.fy=n.y; n.pinned=true; } });
  }
  sim.nodes(GRAPH.nodes);
  sim.force('link').links(GRAPH.links);
  if(!frozen) sim.alpha(Math.max(sim.alpha(),.5)).restart();

  link = gLink.selectAll('line').data(GRAPH.links, d=>d.key)
    .join('line')
    .attr('class',d=>'link '+d.rel);
  updateFlow();

  const nodeSel = gNode.selectAll('g.node').data(GRAPH.nodes, d=>d.id);
  nodeSel.exit().remove();
  const nodeEnter = nodeSel.enter().append('g').call(drag)
    .on('mouseenter',(e,d)=>showTip(e,d))
    .on('mousemove',(e)=>positionTip(e))
    .on('mouseleave',hideTip)
    .on('click',(e,d)=>{e.stopPropagation();select(d.id);});
  node = nodeEnter.merge(nodeSel);
  node.attr('class',d=>'node role-'+d.role+(d.seen?'':' phantom')+(d.role==='ap'||d.role==='ssid'?' showlabel':''));
  node.each(function(d){ drawNode(d3.select(this), d); });

  renderLegend();
  renderStats();
  renderAlertsFeed();
  applyFilter();
  applyFade();
  document.getElementById('empty').style.display = GRAPH.nodes.length ? 'none' : 'grid';

  if(selected!==null){
    if(nodeById.has(selected)) select(selected,false);
    else select(null);
  }
  firstApply = false;
}

svg.on('click',()=>select(null));

function renderPositions(){
  link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  node.attr('transform',d=>`translate(${d.x},${d.y})`);
}
sim.on('tick', renderPositions);

// ---- scope rotation: sweep every contact around the centre, radar-style ----
// Rotates the node POSITIONS (not a group transform) so hover / click / pan /
// drag all keep working. Runs on its own rAF so it continues after the layout
// has settled; the centre matches the backdrop rings' centre (W/2,H/2).
let rotSpeed = 0;              // degrees per second (0 = off)
let rotLast = 0, rotRAF = null;
function rotTick(now){
  if(rotSpeed===0){ rotRAF=null; return; }
  const dt=Math.min(0.05,(now-(rotLast||now))/1000); rotLast=now;
  const a=rotSpeed*dt*Math.PI/180, cs=Math.cos(a), sn=Math.sin(a), cx=W/2, cy=H/2;
  GRAPH.nodes.forEach(n=>{
    let dx=n.x-cx, dy=n.y-cy;
    n.x=cx+dx*cs-dy*sn; n.y=cy+dx*sn+dy*cs;
    if(n.fx!=null){ dx=n.fx-cx; dy=n.fy-cy; n.fx=cx+dx*cs-dy*sn; n.fy=cy+dx*sn+dy*cs; }
  });
  renderPositions();
  rotRAF=requestAnimationFrame(rotTick);
}
function startRot(){ if(rotSpeed!==0 && !rotRAF){ rotLast=0; rotRAF=requestAnimationFrame(rotTick); } }

// ---- zoom ----
const zoom = d3.zoom().scaleExtent([.15,6]).on('zoom',e=>{
  root.attr('transform',e.transform);
  gNode.classed('zoomed',e.transform.k>1.6);
  node.classed('showlabel',d=> (d.role==='ap'||d.role==='ssid') || e.transform.k>1.6);
});
svg.call(zoom);

function fit(){
  const pad=80;
  const xs=GRAPH.nodes.map(d=>d.x), ys=GRAPH.nodes.map(d=>d.y);
  if(!xs.length)return;
  const x0=Math.min(...xs),x1=Math.max(...xs),y0=Math.min(...ys),y1=Math.max(...ys);
  const w=x1-x0||1,h=y1-y0||1;
  const k=Math.min(6,Math.max(.15,.9*Math.min(W/(w+pad*2),H/(h+pad*2))));
  const tx=W/2-k*(x0+x1)/2, ty=H/2-k*(y0+y1)/2;
  svg.transition().duration(500).call(zoom.transform,d3.zoomIdentity.translate(tx,ty).scale(k));
}

function select(id, pan=true){
  selected=id;
  if(id===null){
    document.body.classList.remove('has-selection');
    node.classed('dim',false).classed('hot',false);
    link.classed('dim',false).classed('hot',false);
    applyFade();                       // restore activity-fade opacities
    return;
  }
  node.style('opacity',null);          // let the dim/hot classes own opacity
  const nbrs=new Set([id]); adj.get(id).forEach(a=>nbrs.add(a.id));
  node.classed('hot',d=>d.id===id).classed('dim',d=>!nbrs.has(d.id));
  link.classed('hot',l=>((l.source.id||l.source)===id||(l.target.id||l.target)===id))
      .classed('dim',l=>!(((l.source.id||l.source)===id)||((l.target.id||l.target)===id)));
  document.body.classList.add('has-selection');
  fillDossier(nodeById.get(id));
  if(pan){
    const d=nodeById.get(id);
    const t=d3.zoomTransform(svg.node());
    svg.transition().duration(400)
       .call(zoom.transform, d3.zoomIdentity.translate(W/2-t.k*d.x,H/2-t.k*d.y).scale(t.k));
  }
}

function secFact(d){
  // returns [label, valueHTML, isRisk] for the Security fact, or null
  const t=CRYPT[d.crypt_tier];
  if(!t && !d.wps) return null;
  let v = t ? esc(d.crypt||t.name) : 'Encrypted';
  if(d.wps) v += '<span class="badge">WPS</span>';
  return ['Security', v, (t&&t.risk)||d.wps];
}
function sparkSVG(hist){
  // signal history minute-vector -> inline sparkline; zeros = "no sample" gaps
  const pts=hist.map((v,i)=>({i,v})).filter(p=>p.v);   // drop blank slots
  if(pts.length<2) return '';
  const w=296,h=34,pad=3;
  const xs=hist.length-1;
  const lo=Math.min(...pts.map(p=>p.v)), hi=Math.max(...pts.map(p=>p.v));
  const span=(hi-lo)||1;
  const X=i=>pad+(i/xs)*(w-2*pad);
  const Y=v=>pad+(1-(v-lo)/span)*(h-2*pad);
  const line=pts.map((p,k)=>(k?'L':'M')+X(p.i).toFixed(1)+','+Y(p.v).toFixed(1)).join(' ');
  const last=pts[pts.length-1];
  const area=`M${X(pts[0].i).toFixed(1)},${h-pad} `+
    pts.map(p=>'L'+X(p.i).toFixed(1)+','+Y(p.v).toFixed(1)).join(' ')+
    ` L${X(last.i).toFixed(1)},${h-pad} Z`;
  return `<div class="spark"><div class="k" style="margin-bottom:4px">Signal history `+
    `<span style="color:var(--muted)">${hi} … ${lo} dBm</span></div>`+
    `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`+
    `<path class="sarea" fill="${sigColor(last.v)}" d="${area}"/>`+
    `<path class="sline" stroke="${sigColor(last.v)}" d="${line}"/>`+
    `<circle class="sdot" fill="${sigColor(last.v)}" cx="${X(last.i).toFixed(1)}" cy="${Y(last.v).toFixed(1)}" r="2.4"/>`+
    `</svg></div>`;
}
function pktSparkSVG(hist){
  // packet-rate minute-vector -> filled sparkline (zeros are real: no traffic)
  if(!hist||!hist.length) return '';
  const total=hist.reduce((a,b)=>a+(b>0?b:0),0);
  if(!total) return '';
  const w=296,h=30,pad=2,n=hist.length,hi=Math.max(...hist,1);
  const X=i=>pad+(i/(n-1))*(w-2*pad);
  const Y=v=>pad+(1-Math.max(0,v)/hi)*(h-2*pad);
  const line=hist.map((v,i)=>(i?'L':'M')+X(i).toFixed(1)+','+Y(v).toFixed(1)).join(' ');
  const area=`M${X(0).toFixed(1)},${h-pad} `+
    hist.map((v,i)=>'L'+X(i).toFixed(1)+','+Y(v).toFixed(1)).join(' ')+
    ` L${X(n-1).toFixed(1)},${h-pad} Z`;
  const c='#F5A524';
  return `<div class="spark"><div class="k" style="margin-bottom:4px">Packet rate `+
    `<span style="color:var(--muted)">~${total.toLocaleString()}/min · peak ${hi}/s</span></div>`+
    `<svg viewBox="0 0 ${w} ${h}" preserveAspectRatio="none">`+
    `<path class="sarea" fill="${c}" d="${area}"/>`+
    `<path class="sline" stroke="${c}" d="${line}"/></svg></div>`;
}
function fillDossier(d){
  const r=ROLE[d.role];
  document.getElementById('d-role').innerHTML=
    `<span style="width:9px;height:9px;border-radius:50%;background:${r.c};display:inline-block"></span>${r.name}`;
  document.getElementById('d-title').textContent=d.label||d.mac||'—';
  document.getElementById('d-mac').textContent=d.mac||'';
  const facts=[];       // each: [key, value] or [key, value, {risk, wide, raw}]
  const sec=secFact(d);
  if(sec) facts.push([sec[0], sec[1], {risk:sec[2], wide:true, raw:true}]);
  if(d.role!=='ssid'){
    facts.push(['Vendor',d.manuf||'—']);
    let chan=d.channel||'—';
    if(d.band) chan+=' · '+d.band+' GHz';
    facts.push(['Channel',chan]);
    if(d.ht_mode) facts.push(['Width',d.ht_mode]);
    facts.push(['Signal',d.sig!=null?d.sig+' dBm':'—']);
    if(d.sig_min!=null&&d.sig_max!=null&&d.sig_min!==d.sig_max)
      facts.push(['Signal range',d.sig_min+' … '+d.sig_max+' dBm']);
    if(d.txpower) facts.push(['TX power',d.txpower+' dBm']);
    facts.push(['Packets',d.packets?d.packets.toLocaleString():'—']);
    if(d.datasize) facts.push(['Data',fmtBytes(d.datasize)]);
    if(d.n_assoc) facts.push(['Assoc. clients',String(d.n_assoc)]);
    if(d.n_probed) facts.push(['Probed SSIDs',String(d.n_probed)]);
    if(d.country) facts.push(['Regulatory',d.country]);
    if(d.first)facts.push(['First seen',fmt(d.first)]);
    if(d.last)facts.push(['Last seen',fmt(d.last)]);
    if(d.probes&&d.probes.length)facts.push(['Probing',d.probes.slice(0,6).join(', ')]);
    if(!d.seen)facts.push(['Note','referenced only — not directly captured']);
  }else{
    facts.push(['Members',String(adj.get(d.id).length)]);
    if(d.band) facts.push(['Band',d.band+' GHz']);
  }
  document.getElementById('d-facts').innerHTML=facts.map(f=>{
    const o=f[2]||{};
    const val=o.raw?f[1]:esc(f[1]);
    return `<div class="fact${o.wide?' wide':''}"><div class="k">${f[0]}</div>`+
      `<div class="v${o.risk?' risk':''}">${val}</div></div>`;
  }).join('')
    + (layers.sigspark && d.role!=='ssid'?sparkSVG(d.sig_hist||[]):'')
    + (layers.pktspark && d.role!=='ssid'?pktSparkSVG(d.pkt_hist||[]):'');
  // alerts naming this device
  const al=(alertsById.get(d.id)||[]).slice().sort((x,y)=>y.ts-x.ts);
  document.getElementById('d-alerts').innerHTML = al.length ?
    `<div class="eyebrow">⚠ Alerts · ${al.length}</div>` + al.slice(0,8).map(a=>
      `<div class="da"><div class="h">${esc(a.header)}</div>`+
      (a.text?`<div class="x">${esc(a.text)}</div>`:'')+
      `<div class="t">${a.ts?fmt(a.ts):''}${a.channel?' · ch '+esc(a.channel):''}</div></div>`
    ).join('') : '';
  const conns=adj.get(d.id).map(a=>({n:nodeById.get(a.id),rel:a.rel}))
    .sort((x,y)=>(y.n.degree)-(x.n.degree));
  const relName={assoc:'assoc',advertise:'ssid',probe:'probe',radio:'same AP'};
  document.getElementById('d-conn').innerHTML = conns.length? conns.map(c=>
    `<a data-id="${esc(c.n.id)}"><span class="dot" style="background:${ROLE[c.n.role].c}"></span>`+
    `<span class="lbl">${esc(c.n.label||c.n.mac)}</span><span class="rel">${relName[c.rel]||c.rel}</span></a>`
  ).join('') : '<div style="padding:8px;color:var(--faint);font-family:var(--mono);font-size:12px">no links</div>';
  document.querySelectorAll('#d-conn a').forEach(a=>
    a.onclick=()=>select(a.getAttribute('data-id')));
}
document.getElementById('dclose').onclick=()=>select(null);

// ---- tooltip ----
const tip=document.getElementById('tip');
function showTip(e,d){
  const rows=[`<div class="t-lbl">${esc(d.label||d.mac)}</div>`];
  rows.push(`<div class="t-row">${ROLE[d.role].name}${d.mac&&d.mac!==d.label?' · '+esc(d.mac):''}</div>`);
  if(d.manuf)rows.push(`<div class="t-row">${esc(d.manuf)}</div>`);
  const bits=[];
  if(d.channel)bits.push('ch '+esc(d.channel));
  if(d.band)bits.push(d.band+'G');
  if(d.sig!=null)bits.push('<b>'+d.sig+' dBm</b>');
  if(d.packets)bits.push(d.packets.toLocaleString()+' pkts');
  if(bits.length)rows.push(`<div class="t-row">${bits.join(' · ')}</div>`);
  const t=CRYPT[d.crypt_tier];
  if(t||d.wps){
    const risk=(t&&t.risk)||d.wps;
    const txt=(t?t.name:'Encrypted')+(d.wps?' + WPS':'');
    rows.push(`<div class="t-row" style="color:${risk?'#FF8A96':'var(--muted)'}">${risk?'⚠ ':''}${esc(txt)}</div>`);
  }
  if(d.act>0){
    rows.push(`<div class="t-row" style="color:#7FE3DA">▲ active · ~${d.act.toLocaleString()} pkt/min</div>`);
  }
  if(d.alerts>0){
    const al=alertsById.get(d.id)||[];
    const hdr=al[0]?al[0].header:'';
    rows.push(`<div class="t-row" style="color:#FF8A96">⚠ ${d.alerts} alert${d.alerts>1?'s':''}${hdr?' · '+esc(hdr):''}</div>`);
  }
  rows.push(`<div class="t-row" style="color:var(--faint);margin-top:2px">${adj.get(d.id).length} links</div>`);
  tip.innerHTML=rows.join(''); tip.style.opacity=1; positionTip(e);
}
function positionTip(e){
  const p=14,r=tip.getBoundingClientRect();
  let x=e.clientX+p,y=e.clientY+p;
  if(x+r.width>W)x=e.clientX-r.width-p;
  if(y+r.height>H)y=e.clientY-r.height-p;
  tip.style.left=x+'px';tip.style.top=y+'px';
}
function hideTip(){tip.style.opacity=0;}

// ---- search ----
document.getElementById('search').addEventListener('input',ev=>{
  const q=ev.target.value.trim().toLowerCase();
  if(!q){node.classed('match',false);return;}
  let first=null;
  node.classed('match',d=>{
    const hay=[d.label,d.mac,d.manuf,d.crypt,...(d.ssids||[]),...(d.probes||[])]
      .filter(Boolean).join(' ').toLowerCase();
    const hit=hay.includes(q);
    if(hit&&!first)first=d;
    return hit;
  });
  if(ev.inputType===undefined||ev.key==='Enter'){}
});
document.getElementById('search').addEventListener('keydown',ev=>{
  if(ev.key!=='Enter')return;
  const q=ev.target.value.trim().toLowerCase();
  const hit=GRAPH.nodes.find(d=>[d.label,d.mac,d.manuf,d.crypt,...(d.ssids||[]),...(d.probes||[])]
    .filter(Boolean).join(' ').toLowerCase().includes(q));
  if(hit)select(hit.id);
});

// ---- legend: contact-type filters + a toggle for every visual layer ----
const hidden=new Set();
// the visual layers, with a swatch that previews each one
const LAYER_SECTIONS=[
  {title:'Links', items:[
    {k:'assoc',     label:'Association',    sw:'<span class="sw-line" style="--c:var(--line-strong)"></span>'},
    {k:'advertise', label:'SSID advertise', sw:'<span class="sw-line" style="--c:rgba(245,165,36,.75)"></span>'},
    {k:'probe',     label:'Probe request',  sw:'<span class="sw-line dash" style="--c:rgba(255,92,138,.85)"></span>'},
    {k:'radio',     label:'Same-AP radio',  sw:'<span class="sw-line" style="--c:var(--ap);height:3px"></span>'},
    {k:'flow',      label:'Traffic flow',   sw:'<span class="sw-line dash" style="--c:rgba(120,214,206,.95)"></span>'},
  ]},
  {title:'Signal & status', items:[
    {k:'gauge',    label:'Signal gauge',  sw:'<svg width="14" height="14" viewBox="0 0 14 14"><path d="M7,1.4 A5.6,5.6 0 1 1 2.6,10.4" fill="none" stroke="#34D6CE" stroke-width="2" stroke-linecap="round"/></svg>'},
    {k:'fade',     label:'Activity fade', sw:'<span class="sw-fade"></span>'},
    {k:'security', label:'Security ring', sw:'<span class="sw-ring dash" style="--c:#FF9F45"></span>'},
    {k:'alert',    label:'Alert ring',    sw:'<span class="sw-ring" style="--c:#FF3B57"></span>'},
  ]},
  {title:'Activity', items:[
    {k:'glow',     label:'Busy glow',    sw:'<span class="sw-glow"></span>'},
    {k:'ping',     label:'Live ping',    sw:'<span class="sw-ring" style="--c:#EAF2FF"></span>'},
    {k:'sigspark', label:'Signal graph', sw:'<svg width="18" height="10" viewBox="0 0 18 10"><polyline points="0,8 4,3 8,6 12,2 18,5" fill="none" stroke="#34D6CE" stroke-width="1.4"/></svg>'},
    {k:'pktspark', label:'Packet graph', sw:'<svg width="18" height="10" viewBox="0 0 18 10"><polyline points="0,9 3,5 6,7 9,2 12,6 15,4 18,8" fill="none" stroke="#F5A524" stroke-width="1.4"/></svg>'},
  ]},
  {title:'Scope', items:[
    {k:'backdrop', label:'Radar backdrop', sw:'<svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="6" fill="none" stroke="var(--faint)" stroke-width="1"/><circle cx="7" cy="7" r="3" fill="none" stroke="var(--faint)" stroke-width="1"/></svg>'},
  ]},
];
let legendOpen=false;   // collapsed by default: contacts only
function buildLegendChrome(){
  let html='<div class="leg-top" id="legend-toggle" title="Show/hide the visual layers">'
    +'<span class="eyebrow">Contacts</span>'
    +'<span class="leg-caret" id="legend-caret"></span></div>'
    +'<div id="leg-contacts"></div>'
    +'<div id="legend-layers">';
  for(const sec of LAYER_SECTIONS){
    html+=`<div class="eyebrow leg-h">${sec.title}</div>`;
    for(const it of sec.items)
      html+=`<div class="chip lay" data-layer="${it.k}"><span class="sw">${it.sw}</span><span class="lbl2">${it.label}</span></div>`;
  }
  html+='</div>';
  document.getElementById('legend').innerHTML=html;
  document.querySelectorAll('#legend .chip.lay').forEach(c=>{
    const k=c.getAttribute('data-layer');
    c.classList.toggle('off',!layers[k]);
    c.onclick=()=>{ layers[k]=!layers[k]; c.classList.toggle('off',!layers[k]); applyLayers(); };
  });
  document.getElementById('legend-toggle').onclick=()=>{ legendOpen=!legendOpen; syncLegendOpen(); };
  syncLegendOpen();
}
function syncLegendOpen(){
  document.getElementById('legend-layers').style.display=legendOpen?'':'none';
  document.getElementById('legend-caret').textContent=legendOpen?'▴ layers':'▾ layers';
}
function renderLegend(){
  const counts={}; GRAPH.nodes.forEach(n=>counts[n.role]=(counts[n.role]||0)+1);
  const chips=d3.select('#leg-contacts').selectAll('.chip').data(ORDER.filter(r=>counts[r]), r=>r);
  chips.exit().remove();
  const enter=chips.enter().append('div').attr('class','chip').attr('data-role',r=>r)
    .on('click',function(){
      const r=d3.select(this).datum();
      if(hidden.has(r))hidden.delete(r); else hidden.add(r);
      d3.select(this).classed('off',hidden.has(r));
      applyFilter();
    });
  enter.append('span').attr('class',r=>'dot'+(r==='ssid'?' d':'')).style('background',r=>ROLE[r].c);
  enter.append('span').attr('class','label');
  enter.append('span').attr('class','n');
  const all=enter.merge(chips);
  all.classed('off',r=>hidden.has(r));
  all.select('.label').text(r=>ROLE[r].name);
  all.select('.n').text(r=>counts[r]);
}
function applyFilter(){
  // role filter: hide a contact type and its links. Composes with the per-layer
  // link-type toggles (those hide via a `no-KEY` body class in CSS), because we
  // only ever set an inline display of 'none' (role hidden) or null (defer to CSS).
  node.style('display',d=>hidden.has(d.role)?'none':null);
  link.style('display',d=>{
    const s=d.source, t=d.target;
    return (hidden.has(s.role)||hidden.has(t.role))?'none':null;
  });
}

// ---- stats ----
function renderStats(){
  const counts={}; GRAPH.nodes.forEach(n=>counts[n.role]=(counts[n.role]||0)+1);
  const statDefs=[['nodes',GRAPH.nodes.length],['links',GRAPH.links.length],
    ['APs',counts.ap||0],['clients',counts.client||0]];
  if(allAlerts.length) statDefs.push(['alerts',allAlerts.length,'alert']);
  document.getElementById('stats').innerHTML=statDefs.map(s=>
    `<div class="stat${s[2]?' '+s[2]:''}"><div class="v">${s[1].toLocaleString()}</div><div class="k">${s[0]}</div></div>`).join('');
}

// ---- alerts feed (top-centre panel) ----
function alertAge(ts){
  const now = estimatedNow() || graphMaxLast || (Date.now()/1000);
  const s = Math.max(0, Math.round(now-ts));
  if(s<60) return s+'s';
  if(s<3600) return Math.round(s/60)+'m';
  if(s<86400) return Math.round(s/3600)+'h';
  return Math.round(s/86400)+'d';
}
let alertsExpanded=false;
const ALERTS_COLLAPSED=6;
function renderAlertsFeed(){
  const panel=document.getElementById('alerts');
  if(!allAlerts.length){ panel.style.display='none'; return; }
  panel.style.display='block';
  document.getElementById('alerts-head').innerHTML=
    `<span class="adot"></span>Alerts · ${allAlerts.length}`;
  const show=alertsExpanded?allAlerts:allAlerts.slice(0,ALERTS_COLLAPSED);
  const rows=show.map(a=>{
    const n=a.id!=null?nodeById.get(a.id):null;
    const who=n?(n.label||n.mac):(a.mac||'—');
    const linked=!!n;
    return `<div class="arow${linked?'':' unlinked'}"${linked?` data-id="${esc(a.id)}"`:''}>`+
      `<span class="ah">${esc(a.header)}</span>`+
      `<span class="ad">${esc(who)}</span>`+
      `<span class="at">${alertAge(a.ts)}</span></div>`;
  }).join('');
  let toggle='';
  if(allAlerts.length>ALERTS_COLLAPSED){
    toggle=`<div class="amore" id="alerts-toggle">`+
      (alertsExpanded?'▴ show less':`▾ +${allAlerts.length-ALERTS_COLLAPSED} more`)+`</div>`;
  }
  const list=document.getElementById('alerts-list');
  list.classList.toggle('expanded', alertsExpanded);
  list.innerHTML=rows+toggle;
  panel.querySelectorAll('.arow[data-id]').forEach(el=>
    el.onclick=()=>select(el.getAttribute('data-id')));
  const tog=document.getElementById('alerts-toggle');
  if(tog) tog.onclick=()=>{ alertsExpanded=!alertsExpanded; renderAlertsFeed(); };
}

// ---- control wiring ----
const chargeEl=document.getElementById('charge'), distEl=document.getElementById('dist');
const chargeV=document.getElementById('chargeV'), distV=document.getElementById('distV');
const spinEl=document.getElementById('spin'), spinV=document.getElementById('spinV');
function applySpin(){
  const v=+spinEl.value;                  // 0 = off, else degrees/second
  if(v<=0){ rotSpeed=0; spinV.textContent='off'; }
  else{
    rotSpeed=v*0.30;                      // v:1..100 -> 0.3 .. 30 deg/s
    spinV.textContent=Math.round(360/rotSpeed)+'s/turn';
    startRot();
  }
}
function syncLabels(){chargeV.textContent=chargeEl.value;distV.textContent=distEl.value;}
syncLabels(); applySpin();
chargeEl.oninput=()=>{sim.force('charge').strength(-chargeEl.value);sim.alpha(.5).restart();syncLabels();};
distEl.oninput=()=>{baseDist=+distEl.value;sim.force('link').distance(linkDist);sim.alpha(.5).restart();syncLabels();};
spinEl.oninput=applySpin;
document.getElementById('fit').onclick=fit;
let frozen=false;
document.getElementById('freeze').onclick=function(){
  frozen=!frozen; this.textContent=frozen?'Release':'Freeze';
  if(frozen){GRAPH.nodes.forEach(d=>{d.fx=d.x;d.fy=d.y;d.pinned=true;});sim.stop();}
  else{GRAPH.nodes.forEach(d=>{d.fx=null;d.fy=null;d.pinned=false;});sim.alpha(.4).restart();}
};

// ---- helpers ----
function fmt(ts){try{return new Date(ts*1000).toLocaleString();}catch(e){return String(ts);}}
function fmtBytes(n){
  if(!n)return '0 B';
  const u=['B','KB','MB','GB','TB']; let i=0,v=n;
  while(v>=1024&&i<u.length-1){v/=1024;i++;}
  return (v>=10||i===0?Math.round(v):v.toFixed(1))+' '+u[i];
}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));}
window.addEventListener('resize',()=>{
  W=window.innerWidth;H=window.innerHeight;drawBack();
  sim.force('center',d3.forceCenter(W/2,H/2)).alpha(.2).restart();
});
document.addEventListener('keydown',e=>{if(e.key==='Escape')select(null);});

// ---- initial render ----
buildLegendChrome();     // static legend sections + layer toggles (once)
apply(GRAPH);
applyLayers();           // sync body classes / flow / fade to the toggle state
setTimeout(fit,700);

// ---- live polling ----
const pulseEl=document.getElementById('pulse'), liveStatusEl=document.getElementById('liveStatus');
let lastUpdated=Date.now(), liveError=null;
function renderLiveStatus(){
  if(!LIVE)return;
  liveStatusEl.style.display='block';
  const secs=Math.max(0,Math.round((Date.now()-lastUpdated)/1000));
  liveStatusEl.textContent = liveError ? `stalled — ${liveError}` : `live · updated ${secs}s ago`;
  const stale = !liveError && secs>(POLL_MS/1000)*3;
  liveStatusEl.classList.toggle('stale', stale || !!liveError);
  pulseEl.classList.toggle('err', stale || !!liveError);
}
if(LIVE){
  async function poll(){
    try{
      const res=await fetch('/graph.json',{cache:'no-store'});
      const payload=await res.json();
      liveError=payload.error||null;
      if(payload.updated){ lastUpdated=payload.updated*1000; pollServerTime=payload.updated; pollWall=Date.now(); }
      if(!payload.error) apply(payload.graph);
    }catch(e){
      liveError=(e&&e.message)||'fetch failed';
    }
    renderLiveStatus();
  }
  poll();
  setInterval(poll, POLL_MS);
  setInterval(()=>{
    renderLiveStatus();
    // advance the fade between polls so quiet contacts keep dimming
    refTime = Math.max(graphMaxLast, estimatedNow());
    applyFade();
  }, 1000);
}
renderLiveStatus();
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Render
# ---------------------------------------------------------------------------
def render_html(graph, title, source_label, live=False, poll_ms=5000):
    data = json.dumps(graph, separators=(",", ":"))
    out = TEMPLATE.replace("/*__DATA__*/", data)
    out = out.replace("__TITLE__", title)
    out = out.replace("__SOURCE__", source_label)
    out = out.replace("__LIVE__", "true" if live else "false")
    out = out.replace("__POLL_MS__", str(poll_ms))
    return out


# ---------------------------------------------------------------------------
# Live mode: poll the Kismet API in the background and serve the page +
# up-to-date graph JSON from a small local HTTP server, so the scope in the
# browser keeps discovering devices as Kismet does.
# ---------------------------------------------------------------------------
def _lan_ip():
    """Best-effort primary LAN IP of this host (no packets are actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("192.168.255.255", 1))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def serve_live(args, html_out, initial_graph):
    state = {"graph": initial_graph, "html": html_out.encode("utf-8"),
             "error": None, "updated": time.time()}
    lock = threading.Lock()
    stop = threading.Event()

    def poll_once():
        devices = load_from_api(args.api, args.user, args.password,
                                args.apikey, args.active_since)
        alerts = load_alerts_from_api(args.api, args.user, args.password,
                                      args.apikey, args.active_since)
        return build_graph(devices, include_ssids=not args.no_ssids,
                           link_radios=not args.no_radio_links,
                           radio_prefix=args.radio_prefix, alerts=alerts)

    def poll_loop():
        while not stop.is_set():
            try:
                graph = poll_once()
                with lock:
                    state["graph"] = graph
                    state["error"] = None
                    state["updated"] = time.time()
            except SystemExit as e:
                with lock:
                    state["error"] = str(e.code if e.code else e)
            except Exception as e:
                with lock:
                    state["error"] = str(e)
            stop.wait(args.interval)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *a):
            pass

        def _send(self, status, body, content_type):
            body = body if isinstance(body, bytes) else body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            if content_type == "application/json":
                self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                with lock:
                    body = state["html"]
                self._send(200, body, "text/html; charset=utf-8")
            elif self.path == "/graph.json":
                with lock:
                    payload = json.dumps({
                        "graph": state["graph"],
                        "updated": state["updated"],
                        "error": state["error"],
                    }).encode("utf-8")
                self._send(200, payload, "application/json")
            else:
                self._send(404, b"not found", "text/plain")

    poller = threading.Thread(target=poll_loop, daemon=True)
    poller.start()

    try:
        server = ThreadingHTTPServer((args.bind, args.port), Handler)
    except OSError as e:
        stop.set()
        sys.exit(f"error: cannot bind {args.bind}:{args.port}: {e}")

    print(f"Live scope serving (polling {args.api} every {args.interval:g}s — Ctrl-C to stop)")
    if args.bind in ("0.0.0.0", "::", ""):
        lan = _lan_ip()
        print(f"  local:   http://127.0.0.1:{args.port}/")
        if lan:
            print(f"  network: http://{lan}:{args.port}/   (reachable from other devices on your LAN)")
        else:
            print(f"  network: http://<this-host-ip>:{args.port}/   (reachable from other devices on your LAN)")
    else:
        host = args.bind if ":" not in args.bind else f"[{args.bind}]"
        print(f"  http://{host}:{args.port}/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        stop.set()
        server.shutdown()


def main():
    ap = argparse.ArgumentParser(
        description="Build an interactive device-relationship scope from Kismet data.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--db", help="path to a .kismetdb log database")
    src.add_argument("--api", metavar="URL", help="base URL of a live Kismet server, e.g. http://host:2501")
    ap.add_argument("--user", help="Kismet API username (basic auth)")
    ap.add_argument("--password", help="Kismet API password")
    ap.add_argument("--apikey", help="Kismet API key (alternative to user/password)")
    ap.add_argument("--active-since", type=int, metavar="SECONDS",
                    help="API only: restrict to devices seen in the last N seconds")
    ap.add_argument("--no-ssids", action="store_true",
                    help="do not add SSID network nodes (device-to-device only)")
    ap.add_argument("--no-radio-links", action="store_true",
                    help="do not link BSSIDs that belong to the same physical AP")
    ap.add_argument("--radio-prefix", type=int, default=5, metavar="OCTETS",
                    help="MAC octets that must match to treat APs as one radio (default 5)")
    ap.add_argument("--live", action="store_true",
                    help="keep discovering: start a local server that polls --api in the "
                         "background and pushes updates into the open page as Kismet finds devices")
    ap.add_argument("--interval", type=float, default=5.0, metavar="SECONDS",
                    help="--live: how often to poll the Kismet API (default 5s)")
    ap.add_argument("--port", type=int, default=8765, metavar="PORT",
                    help="--live: server port (default 8765)")
    ap.add_argument("--bind", default="127.0.0.1", metavar="ADDR",
                    help="--live: address to bind the server to. Default 127.0.0.1 "
                         "(this machine only); use 0.0.0.0 to expose it on your "
                         "internal network")
    ap.add_argument("-o", "--output", default="kismet_graph.html", help="output HTML file")
    ap.add_argument("-t", "--title", default="Kismet Relation Scope", help="visualisation title")
    args = ap.parse_args()

    if args.live and not args.api:
        ap.error("--live requires --api (a live Kismet source)")

    if args.db:
        devices = load_from_db(args.db)
        alerts = load_alerts_from_db(args.db)
        source_label = os.path.basename(args.db)
    else:
        devices = load_from_api(args.api, args.user, args.password,
                                args.apikey, args.active_since)
        alerts = load_alerts_from_api(args.api, args.user, args.password,
                                      args.apikey, args.active_since)
        source_label = args.api

    if not devices and not args.live:
        sys.exit("No Wi-Fi devices found in the source.")

    graph = build_graph(devices, include_ssids=not args.no_ssids,
                        link_radios=not args.no_radio_links,
                        radio_prefix=args.radio_prefix, alerts=alerts)
    html_out = render_html(graph, args.title, source_label,
                           live=args.live, poll_ms=int(args.interval * 1000))
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html_out)

    roles = {}
    for n in graph["nodes"]:
        roles[n["role"]] = roles.get(n["role"], 0) + 1
    print(f"Loaded {len(devices)} Wi-Fi devices from {source_label}")
    print(f"Graph: {len(graph['nodes'])} nodes, {len(graph['links'])} links"
          + (f", {len(graph['alerts'])} alerts" if graph.get("alerts") else ""))
    print("  " + ", ".join(f"{k}: {v}" for k, v in sorted(roles.items())))
    print(f"Wrote {args.output}")

    if args.live:
        serve_live(args, html_out, graph)


if __name__ == "__main__":
    main()
