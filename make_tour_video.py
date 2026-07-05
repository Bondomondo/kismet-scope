#!/usr/bin/env python3
"""make_tour_video.py — build the scripted "guided tour" player HTML.

A long, instructional walkthrough that drives every feature of the scope with a
synthetic cursor and captions, on a slightly richer synthetic dataset (extra
alerts so the alerts-feed expand can be shown). Record it with:

    python3 make_tour_video.py
    python3 record_demo.py /home/fredrik/tour-player.html \\
        /home/fredrik/Projects/kismet-visualizer/kismet-scope-guide.mp4 160
"""
import json
import kismet_graph as k
import make_demo as md

OUT = "/home/fredrik/tour-player.html"
T1 = md.T1
M = md   # MAC constants live on make_demo

# richer alert set (fabricated) so the feed's "+N more" expand is demonstrable
_A = [
    ("DEAUTHFLOOD", M.HOME, 30, 10, "Deauth/Disassoc flood on " + M.HOME + " — possible DoS"),
    ("APSPOOF", M.SPOOF, 60, 5, "BSSID " + M.SPOOF + " advertising known SSID HomeNet"),
    ("WPSBRUTE", M.HOME, 95, 8, "WPS PIN brute-force attempts against " + M.HOME),
    ("CRYPTODROP", M.OLD, 130, 6, "Weak WEP encryption still in use on " + M.OLD),
    ("BSSTIMESTAMP", M.FIBER, 160, 4, "Suspicious BSS timestamp jump on " + M.FIBER),
    ("DEAUTHFLOOD", M.MESH1, 205, 10, "Deauthentication flood on " + M.MESH1),
    ("PROBECHAN", M.LAPTOP, 250, 3, "Client " + M.LAPTOP + " probing across many channels"),
    ("APSPOOF", "DE:AD:BE:EF:01:23", 300, 5, "Rogue AP DE:AD:BE:EF:01:23 cloning CoffeeShop"),
]
ALERTS = [{"kismet.alert.header": h, "kismet.alert.transmitter_mac": mac,
           "kismet.alert.timestamp": T1 - off, "kismet.alert.severity": sev,
           "kismet.alert.channel": "6", "kismet.alert.text": txt}
          for (h, mac, off, sev, txt) in _A]
ALERTS = [k.normalize_alert(a) for a in ALERTS]


TOUR = r"""
// ===================== guided-tour director (injected) =====================
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const styl=document.createElement('style');
styl.textContent='@keyframes clk{to{width:36px;height:36px;opacity:0}}';
document.head.appendChild(styl);

// synthetic cursor
const cur=document.createElement('div');
cur.style.cssText='position:fixed;left:0;top:0;z-index:90;pointer-events:none;'
 +'transform:translate(-80px,-80px);transition:transform .55s cubic-bezier(.4,0,.2,1);'
 +'filter:drop-shadow(0 2px 3px rgba(0,0,0,.6))';
cur.innerHTML='<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3,2 L3,17 L7,13 L10,20 L12.5,19 L9.5,12 L15,12 Z" fill="#EAF2FF" stroke="#0A111E" stroke-width="1.2"/></svg>';
document.body.appendChild(cur);
let curX=-80,curY=-80;
async function moveTo(x,y){ curX=x;curY=y; cur.style.transform=`translate(${x-3}px,${y-2}px)`; await sleep(620); }
function clickFx(){ const r=document.createElement('div');
  r.style.cssText=`position:fixed;left:${curX}px;top:${curY}px;width:10px;height:10px;border:2px solid #34D6CE;`
   +`border-radius:50%;z-index:89;pointer-events:none;transform:translate(-50%,-50%);animation:clk .5s ease-out forwards`;
  document.body.appendChild(r); setTimeout(()=>r.remove(),520); }
function center(el){ const r=el.getBoundingClientRect(); return [r.left+r.width/2, r.top+r.height/2]; }
async function moveEl(el){ if(!el)return; const c=center(el); await moveTo(c[0],c[1]); }
async function clickEl(el){ if(!el)return; await moveEl(el); clickFx(); await sleep(140); el.click(); }
function nodeScreen(id){ const d=nodeById.get(id); if(!d)return null; const t=d3.zoomTransform(svg.node());
  return [t.applyX(d.x), t.applyY(d.y)]; }
async function hoverNode(id){ const p=nodeScreen(id); if(!p)return; await moveTo(p[0],p[1]);
  const d=nodeById.get(id); showTip({clientX:p[0],clientY:p[1]}, d); }
async function slide(id,to){ const el=document.getElementById(id); if(!el)return;
  const r=el.getBoundingClientRect(), lo=+el.min, hi=+el.max, fr=(to-lo)/(hi-lo);
  await moveTo(r.left+fr*r.width, r.top+r.height/2);
  const from=+el.value, steps=14; for(let i=1;i<=steps;i++){ el.value=(from+(to-from)*i/steps);
    el.dispatchEvent(new Event('input')); await sleep(70); } }
async function zoomTo(kk){ svg.transition().duration(800).call(zoom.transform,
  d3.zoomIdentity.translate(W/2-kk*W/2,H/2-kk*H/2).scale(kk)); await sleep(900); }

// caption
const cb=document.createElement('div'); cb.style.cssText='position:fixed;left:50%;bottom:26px;'
 +'transform:translateX(-50%);z-index:85;text-align:center;opacity:0;transition:opacity .4s;'
 +'pointer-events:none;max-width:60vw';
cb.innerHTML='<div class="tt" style="font-family:var(--mono);font-size:11px;letter-spacing:.24em;'
 +'text-transform:uppercase;color:#8A9AB8;margin-bottom:6px"></div>'
 +'<div class="ts" style="font-family:var(--sans);font-size:17px;color:#E7EEF9;background:rgba(10,17,30,.74);'
 +'border:1px solid rgba(140,170,220,.34);border-radius:11px;padding:10px 20px;'
 +'box-shadow:0 12px 34px rgba(0,0,0,.55)"></div>';
document.body.appendChild(cb);
function cap(t,s){ cb.querySelector('.tt').textContent=t||''; cb.querySelector('.ts').textContent=s||'';
  cb.style.opacity=(t||s)?'1':'0'; }
document.querySelector('#brand .src span:last-child').textContent='guided tour · demo';

async function toggleLayer(kk){ const sel='.chip.lay[data-layer='+kk+']';
  await clickEl(document.querySelector(sel)); await sleep(1300);
  await clickEl(document.querySelector(sel)); await sleep(500); }

// Real-time capture can hit the auto-fit before the force layout has spread,
// after which nodes drift off-screen. Hold a fixed, whole-graph zoom until the
// sim settles; the tour re-fits once it's stable.
setTimeout(()=>{ const kk=0.6; svg.call(zoom.transform,
  d3.zoomIdentity.translate(W/2-kk*W/2, H/2-kk*H/2).scale(kk)); }, 850);

async function tour(){ try{
  await sleep(2200); fit(); await sleep(1300);
  cap('Kismet · Relation Scope','A guided tour — every device is a radar contact'); await sleep(4200);

  cap('Contacts','Core colour = role: AP, client, bridged, ad-hoc, network'); await sleep(3400);
  cap('Filter','Click a legend row to show or hide that contact type');
  const cc=document.querySelector('#leg-contacts .chip[data-role=client]');
  await clickEl(cc); await sleep(1600); await clickEl(document.querySelector('#leg-contacts .chip[data-role=client]')); await sleep(1500);

  cap('Shape & size','Circles are devices, diamonds are SSID networks · size = links'); await sleep(4200);

  cap('Signal gauge','The ring shows signal strength in dBm — hover any contact');
  await hoverNode('CL_DESKTOP'); await sleep(2700); hideTip();
  await hoverNode('CL_IOT'); await sleep(2700); hideTip(); await sleep(500);

  cap('Security rings','A spinning dashed ring flags open / WEP / WPS networks');
  await hoverNode('AP_CAFE'); await sleep(3100); hideTip(); await sleep(500);

  cap('Activity','Busy devices glow; dashes flow along active links');
  await hoverNode('AP_HOME'); await sleep(3100); hideTip(); await sleep(700);

  cap('Alerts','Kismet IDS alerts — a red feed and pulsing rings. Expand for more');
  const at=document.getElementById('alerts-toggle');
  if(at){ await clickEl(at); await sleep(2600); await clickEl(document.getElementById('alerts-toggle')); await sleep(1400); }
  cap('Alerts','Click an alert to jump straight to the device');
  const ar=document.querySelector('#alerts-list .arow[data-id]');
  if(ar){ await clickEl(ar); await sleep(3200); }
  select(null); fit(); await sleep(800);

  cap('The dossier','Click a contact for security, radio, signal & packet graphs, alerts');
  select('AP_HOME'); await sleep(5200);
  cap('Navigate','Hop through the network via the Connected contacts list');
  const conn=document.querySelector('#d-conn a'); if(conn){ await clickEl(conn); await sleep(3600); }
  select(null); fit(); await sleep(800);

  cap('Search','By MAC, name, SSID, vendor or encryption — e.g. "open"');
  const s=document.getElementById('search'); await moveEl(s); s.focus();
  for(const ch of 'open'){ s.value+=ch; s.dispatchEvent(new Event('input',{bubbles:true})); await sleep(240); }
  await sleep(2000); s.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true})); await sleep(2600);
  s.value=''; s.dispatchEvent(new Event('input',{bubbles:true})); select(null); fit(); await sleep(700);

  cap('Layers','Expand the legend to toggle any visual on or off');
  await clickEl(document.getElementById('legend-toggle')); await sleep(1300);
  await toggleLayer('gauge'); await toggleLayer('glow'); await toggleLayer('security'); await toggleLayer('backdrop');
  await clickEl(document.getElementById('legend-toggle')); await sleep(900);

  cap('Layout','Spread and Link length retune the force layout');
  await slide('charge',760); await sleep(1300); await slide('charge',320); await sleep(900);
  await slide('dist',185); await sleep(1200); await slide('dist',74); await sleep(900);

  cap('Last seen','Hide devices that haven’t been heard recently');
  await slide('lastseen',30); await sleep(2600); await slide('lastseen',100); await sleep(1200);

  cap('Rotation','Sweep the whole scope around the centre, radar-style');
  await slide('spin',32); await sleep(4200); await slide('spin',0); await sleep(1000);

  cap('View','Scroll to zoom, drag to pan — Freeze pins it, Reset refits');
  await zoomTo(1.9); await sleep(1700); await zoomTo(0.55); await sleep(1500);
  await clickEl(document.getElementById('fit')); await sleep(1600);

  cap('Learn more','visual-guide.html  ·  github.com/Bondomondo/kismet-scope'); await sleep(5500);
  cap('','');
 }catch(e){ console.log('TOUR ERROR', e && e.message, e && e.stack); } }

window.__startDemo=()=>tour();
window.__demoDurationMs = 156000;
"""


def main():
    devices = k.load_from_db("demo.kismet")
    graph = k.build_graph(devices, alerts=ALERTS)
    html = k.render_html(graph, "Kismet Relation Scope", "guided tour · demo", live=False)
    html = html.replace("renderLiveStatus();\n</script>", "renderLiveStatus();\n" + TOUR + "\n</script>")
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"Wrote {OUT}  ({len(graph['nodes'])} nodes, {len(graph['links'])} links, {len(ALERTS)} alerts)")


if __name__ == "__main__":
    main()
