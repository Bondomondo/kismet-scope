# Kismet Relation Scope

Turns Kismet Wi-Fi capture data into a single self-contained, interactive
relationship graph — an "RF scope" where every device is a radar contact:
core colour = role (AP / client / bridged / network), ring = signal-strength
gauge (actual dBm), size = number of links, halo = recent traffic. A dashed,
slowly-rotating **warning ring** marks a security risk (open / WEP network, or
WPS enabled), a solid red **alert ring** marks devices flagged by Kismet's IDS,
busy devices **glow and flow** with their packet rate, and contacts that have
gone quiet **fade** so recent activity stands out.

One file, standard library only. No install.

## Try it

A small **synthetic** demo capture ships with the repo — no real network data:

    python3 kismet_graph.py --db demo.kismet -o demo.html

Then open `demo.html`. It's built to show off every visual (all device roles, each
encryption tier, a multi-SSID radio, a phantom client, probes, live activity and a
couple of IDS alerts). Regenerate or tweak it with `python3 make_demo.py`.

## Use

    # From a capture log (.kismetdb):
    python3 kismet_graph.py --db Kismet-20260703-cannon.kismetdb -o scope.html

    # From a live Kismet server (basic auth), last 15 minutes only:
    python3 kismet_graph.py --api http://cannon.local:2501 \
        --user admin --password secret --active-since 900 -o scope.html

    # With an API key instead of user/password:
    python3 kismet_graph.py --api http://127.0.0.1:2501 --apikey ABC123... -o scope.html

    # Live: scope keeps discovering devices as Kismet does
    python3 kismet_graph.py --api http://cannon.local:2501 \
        --user admin --password secret --live -o scope.html

    # Live, reachable from other devices on the internal network:
    python3 kismet_graph.py --api http://cannon.local:2501 \
        --user admin --password secret --live --bind 0.0.0.0 -o scope.html

Then open `scope.html` in a browser. With `--live`, instead open the printed
`http://127.0.0.1:8765/` — that page auto-refreshes as Kismet finds devices;
opening the plain `scope.html` file gives you the frozen snapshot from when it
was written. With `--bind 0.0.0.0` the script also prints a
`http://<lan-ip>:8765/` URL that others on your network can open.

### Options

| flag | meaning |
|------|---------|
| `--db PATH` | read a Kismet log database |
| `--api URL` | read a live Kismet REST server |
| `--user / --password` | basic-auth credentials for `--api` |
| `--apikey KEY` | API key for `--api` (alternative to user/password) |
| `--active-since N` | API only: keep devices seen in the last N seconds |
| `--no-ssids` | device-to-device only; drop the SSID network nodes |
| `--no-radio-links` | don't tie together BSSIDs of the same physical AP |
| `--radio-prefix N` | MAC octets that must match to count as one radio (default 5) |
| `--live` | requires `--api`; starts a local server that keeps polling Kismet and pushes updates into the open page |
| `--interval N` | `--live` only: seconds between polls (default 5) |
| `--port N` | `--live` only: server port (default 8765) |
| `--bind ADDR` | `--live` only: bind address. **Defaults to `127.0.0.1` (this machine only)** — to reach the scope from other devices on your network you must pass `--bind 0.0.0.0` |
| `-o FILE` | output HTML (default `kismet_graph.html`) |
| `-t TITLE` | title shown on the scope |

## In the visualisation

> **New to the scope?** Open [`visual-guide.html`](visual-guide.html) — an illustrated
> reference that shows every colour, ring, gauge, line and animation with a live swatch and
> explains how to read them. It's self-contained; just open it in a browser.

- **Hover** a contact for a readout (vendor, channel, band, dBm, packets,
  security, links).
- **Click** a contact to dim everything else, highlight its neighbours, and open
  a dossier with the full detail Kismet has: security (encryption + WPS), band /
  channel width, signal range and TX power, traffic volume, associated-client and
  probed-SSID counts, regulatory country, first/last seen — plus a **signal
  history** and a **packet-rate** sparkline so you can see how a contact's signal
  and traffic have moved. The dossier's *Connected contacts* list is clickable —
  that's how you hop from device to device.
- **Activity**: devices pushing traffic show it live. A soft **halo** grows and
  brightens with a device's recent packet rate (busy contacts glow, idle beaconers
  stay flat); **dashes flow** along the links of notably-busy devices; and in
  `--live` mode a device **pings** (a quick ripple) the moment new packets arrive
  for it. Hover shows the recent rate (e.g. `▲ active · ~400 pkt/min`). The four
  activity visuals — **Glow** (halo), **Flow**, **Ping**, and **Rate** (the
  dossier's packet sparkline) — each have an on/off toggle under *Activity* in the
  controls panel.
- **Warning ring** (dashed, rotating): the contact is a security risk — an open
  or WEP network, or has WPS enabled. Open networks ring red, WEP orange.
- **Alert ring** (solid, red, pulsing): the device is named in one or more Kismet
  IDS alerts (deauth flood, AP spoof, …). A red **Alerts** panel at the top lists
  recent alerts — click one to jump to the device — and the device's dossier
  shows the full alert text. Alerts naming a device that wasn't captured stay in
  the panel as unlinked entries. (Only present if Kismet raised alerts during the
  capture / session.)
- **Fade**: contacts dim toward the background the longer they've been silent, so
  currently-active devices are the brightest. Live, this tracks real time; on a
  static capture it shades oldest → newest across the capture's span.
- **Search** by MAC, name, SSID, vendor, or encryption (e.g. `open`, `wpa3`);
  Enter jumps to the first match.
- **Legend (bottom-left)** documents *every* visual and lets you switch each on or
  off by clicking it: contact types (filters those nodes), link kinds (association,
  SSID advertise, probe, same-AP radio, traffic flow), signal & status (signal
  gauge, activity fade, security ring, alert ring), activity (busy glow, live ping,
  and the dossier's signal / packet graphs), and the radar backdrop.
- **Spread / Link length** sliders retune the layout; **Ring spin** sets how fast
  the security warning rings rotate (slide to the far left for *off*); **Freeze**
  pins the layout; **Reset view** refits. Scroll to zoom, drag to pan, drag a node
  to reposition.

## Notes

- **This is a relationship map, not a geographic one.** It shows *who talks to
  whom*. A geographic map needs a GPS source during capture — if you log GPS,
  export the `.kismetdb` with `kismetdb_to_kml` for Google Earth instead.
- **Only associated clients appear under an AP.** Kismet infers clients from
  data/association frames, so a client shows up once it has actually joined a
  network (using its stable per-network MAC). Idle devices sending randomised
  probe requests won't appear as clients — but if they probe for named networks,
  they show up linked to those SSID nodes.
- Clients an AP references but that weren't captured directly are drawn as
  hollow dashed contacts.
- **One physical AP, several SSIDs** shows up as several AP contacts, because each
  SSID gets its own BSSID (the radio's base MAC with the last octet incremented).
  Those are tied together with a short glowing amber **"same AP"** link when they
  share the first 5 MAC octets *and* a channel. Relax with `--radio-prefix` or turn
  it off with `--no-radio-links`; the co-channel check keeps unrelated same-vendor
  APs from being merged by mistake.
- **Big captures:** thousands of nodes get busy. Use `--active-since` (API),
  `--no-ssids`, or the legend filters to thin it out.
- **`--live`** keeps the script running in the foreground (Ctrl-C to stop) —
  it polls Kismet in the background and serves the graph to the page over a
  plain local HTTP server on `127.0.0.1`, so your Kismet credentials never
  leave the Python process or reach the browser. New devices fade in as
  they're discovered; with `--active-since` set, devices that age out of the
  window drop back out. **Freeze** still pins the existing layout — newly
  discovered devices are pinned in place too until you release it. If Kismet
  becomes briefly unreachable the last good graph stays on screen and the
  status line in the top-left flags it as stalled.
- **Can't reach the live scope from another device?** The server binds to
  `127.0.0.1` (localhost) by **default**, which is *only* reachable from the
  machine running the script — so `--live` on its own is not visible to the rest
  of your network. Add `--bind 0.0.0.0` and open `http://<this-machine-ip>:8765/`
  from the other device (the startup banner prints that `network:` URL). If it
  still won't connect after rebinding, check the host firewall
  (`sudo ufw status`; allow with `sudo ufw allow 8765/tcp`).
- **`--bind 0.0.0.0`** exposes the live scope to your whole internal network:
  anyone who can reach `http://<your-ip>:8765/` can view the graph (device
  MACs, vendors, SSIDs, signal). The server has no authentication, so only do
  this on a network you trust. Your Kismet credentials still stay server-side —
  the browser only ever receives the finished graph, never the API password.
- The HTML pulls D3 from a CDN, so viewing needs internet the first time. Non-Wi-Fi
  phys (RTL-433, BTLE, ...) are filtered out.
