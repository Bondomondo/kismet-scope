#!/usr/bin/env python3
"""Record a scope "player" HTML to an mp4 via the Chrome DevTools screencast.

Usage: record_demo.py [player.html] [out.mp4] [duration_seconds]
The player must expose window.__startDemo() (triggered once recording is live)
and window.__demoDurationMs.
"""
import asyncio, json, base64, os, shutil, subprocess, sys, time, urllib.request
import websockets

PLAYER = sys.argv[1] if len(sys.argv) > 1 else "/home/fredrik/demo-player.html"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/home/fredrik/kismet-scope-demo.mp4"
DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 34.5
URL = "file://" + os.path.abspath(PLAYER)
PORT = 9222
W, H = 1280, 720
FRAMES = "/home/fredrik/_demo_frames"
USERDIR = "/home/fredrik/_demo_chrome"


def launch():
    for d in (FRAMES, USERDIR):
        shutil.rmtree(d, ignore_errors=True); os.makedirs(d, exist_ok=True)
    args = ["chromium", "--headless=new", f"--remote-debugging-port={PORT}",
            "--remote-allow-origins=*", "--disable-gpu", "--no-sandbox",
            "--hide-scrollbars", "--force-device-scale-factor=1",
            f"--window-size={W},{H}", f"--user-data-dir={USERDIR}", URL]
    return subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def ws_url():
    for _ in range(60):
        try:
            data = json.load(urllib.request.urlopen(f"http://127.0.0.1:{PORT}/json", timeout=1))
            for t in data:
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    return t["webSocketDebuggerUrl"]
        except Exception:
            pass
        time.sleep(0.25)
    raise RuntimeError("no debug target")


async def record():
    url = ws_url()
    async with websockets.connect(url, max_size=None) as ws:
        nid = 0
        async def send(method, params=None):
            nonlocal nid; nid += 1
            await ws.send(json.dumps({"id": nid, "method": method, "params": params or {}}))
        await send("Page.enable")
        await send("Runtime.enable")
        # force an exact WxH viewport so frames are 1280x720 (even dims)
        await send("Emulation.setDeviceMetricsOverride",
                   {"width": W, "height": H, "deviceScaleFactor": 1, "mobile": False})
        await asyncio.sleep(0.3)
        await send("Page.startScreencast", {"format": "jpeg", "quality": 90,
                                            "maxWidth": W, "maxHeight": H, "everyNthFrame": 1})
        await asyncio.sleep(0.4)
        await send("Runtime.evaluate", {"expression": "window.__startDemo && window.__startDemo()"})
        dur = DURATION
        t0 = time.monotonic(); n = 0; times = []
        while time.monotonic() - t0 < dur:
            try:
                msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=2))
            except asyncio.TimeoutError:
                continue
            if msg.get("method") == "Page.screencastFrame":
                p = msg["params"]
                with open(f"{FRAMES}/f{n:05d}.jpg", "wb") as fh:
                    fh.write(base64.b64decode(p["data"]))
                times.append(time.monotonic()); n += 1
                nid += 1
                await ws.send(json.dumps({"id": nid, "method": "Page.screencastFrameAck",
                                          "params": {"sessionId": p["sessionId"]}}))
        await send("Page.stopScreencast")
        return times


def encode(times):
    # frames are captured continuously over the real span -> treat as evenly
    # spaced at fps = count/span, then output constant 30fps mp4
    span = (times[-1] - times[0]) if len(times) > 1 else 1.0
    fps = max(1.0, len(times) / span)
    print(f"  span {span:.1f}s -> {fps:.1f} fps input")
    # pad to a clean 16:9 720p using the scope's background colour (seamless)
    vf = (f"scale={W}:{H}:force_original_aspect_ratio=decrease,"
          f"pad={W}:{H}:(ow-iw)/2:(oh-ih)/2:color=0x0A111E,fps=30")
    subprocess.run(["ffmpeg", "-y", "-framerate", f"{fps:.3f}", "-i", "f%05d.jpg",
                    "-vf", vf, "-r", "30", "-pix_fmt", "yuv420p", "-c:v", "libx264",
                    "-crf", "20", "-movflags", "+faststart", OUT], cwd=FRAMES, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    proc = launch()
    try:
        times = asyncio.run(record())
        print(f"captured {len(times)} frames")
        encode(times)
        sz = os.path.getsize(OUT)
        print(f"wrote {OUT} ({sz/1e6:.1f} MB)")
    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except Exception: proc.kill()
        shutil.rmtree(USERDIR, ignore_errors=True)


if __name__ == "__main__":
    main()
