#!/usr/bin/env python3
"""make_demo_video.py — build the scripted "demo player" HTML for the demo video.

Reuses the real scope (kismet_graph.render_html) but injects a director that
starts with an empty scope and reveals the synthetic demo devices in waves —
simulating a live scan — then narrates a few key visualisations. The companion
record_demo.py captures it to a video.
"""
import json
import kismet_graph as k

DB = "demo.kismet"
OUT = "/home/fredrik/demo-player.html"

# device-reveal waves (cumulative) — tells the "scan discovers devices" story
WAVES = [
    ["AP_HOME"],
    ["AP_CAFE", "AP_OLD"],
    ["AP_FIBER", "AP_MESH1", "AP_MESH2"],
    ["CL_LAPTOP", "CL_PHONE", "CL_DESKTOP", "CL_MESH"],
    ["CL_TABLET", "CL_IOT", "BR_TV", "AD_CAM", "DV_ROAM"],
]


def main():
    devices = k.load_from_db(DB)
    alerts = k.load_alerts_from_db(DB)
    by_key = {d["key"]: d for d in devices}

    # a graph snapshot for each cumulative wave; the final one turns on alerts
    snaps = []
    cume = []
    for i, wave in enumerate(WAVES):
        cume += [by_key[kk] for kk in wave if kk in by_key]
        snaps.append(k.build_graph(cume))
    snaps.append(k.build_graph(cume, alerts=alerts))   # same devices, + alerts

    full = k.build_graph(devices, alerts=alerts)
    html = k.render_html(full, "Kismet Relation Scope", "live scan · demo", live=False)

    director = """
// ===== demo director (injected) =====
apply({nodes:[],links:[],alerts:[]});          // start empty (scan idle)
const SNAPS = __SNAPS__;
// fixed, centred camera so devices just appear within a stable frame
(function(){ const kk=0.78; svg.call(zoom.transform,
  d3.zoomIdentity.translate(W/2-kk*W/2, H/2-kk*H/2).scale(kk)); })();
document.querySelector('#brand .src span:last-child').textContent='live scan · demo';

// caption overlay
const cap=document.createElement('div'); cap.id='vcap';
cap.style.cssText='position:fixed;left:50%;bottom:86px;transform:translateX(-50%);'
 +'font-family:var(--mono);font-size:15px;color:#E7EEF9;background:rgba(10,17,30,.72);'
 +'border:1px solid rgba(140,170,220,.34);border-radius:10px;padding:9px 18px;opacity:0;'
 +'transition:opacity .45s;z-index:60;letter-spacing:.02em;text-align:center;max-width:74vw;'
 +'box-shadow:0 10px 30px rgba(0,0,0,.5)';
document.body.appendChild(cap);
function capS(t){ cap.textContent=t; cap.style.opacity=t?'1':'0'; }

const seq=[
  [ 300, ()=>capS('Scanning started — waiting for devices…') ],
  [1900, ()=>{ apply(SNAPS[0]); capS('First access point discovered'); } ],
  [3700, ()=>{ apply(SNAPS[1]); capS('More APs — spinning rings flag open / WEP networks'); } ],
  [5700, ()=>{ apply(SNAPS[2]); capS('A multi-SSID router: its radios link up'); } ],
  [7700, ()=>{ apply(SNAPS[3]); capS('Clients associate — busy devices glow with traffic'); } ],
  [9900, ()=>{ apply(SNAPS[4]); capS('Bridged, ad-hoc and probing devices join in'); } ],
  [12200,()=>{ apply(SNAPS[5]); capS('⚠ Kismet raises IDS alerts: deauth flood, AP spoof'); } ],
  [15000,()=>{ fit(); } ],
  [16000,()=>{ select('AP_HOME'); capS('Click a contact — security, signal & packet graphs, alerts'); } ],
  [21000,()=>{ select('CL_LAPTOP'); capS('Hop to a busy client'); } ],
  [25000,()=>{ select(null); fit(); capS('Radar sweep'); spinEl.value=26; applySpin(); } ],
  [30000,()=>{ spinEl.value=0; applySpin(); capS('github.com/Bondomondo/kismet-scope'); } ],
  [33500,()=>{ capS(''); } ],
];
// start only when the recorder triggers it, so capture is already live
window.__startDemo=()=>seq.forEach(([t,fn])=>setTimeout(fn,t));
window.__demoDurationMs = 34500;
"""
    director = director.replace("__SNAPS__", json.dumps(snaps, separators=(",", ":")))
    html = html.replace("renderLiveStatus();\n</script>", "renderLiveStatus();\n" + director + "\n</script>")

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Wrote {OUT}  ({len(snaps)} snapshots, "
          f"{len(full['nodes'])} nodes / {len(full['links'])} links / {len(alerts)} alerts)")


if __name__ == "__main__":
    main()
