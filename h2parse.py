# -*- coding: utf-8 -*-
import frida, sys, time, subprocess, threading, gzip, zlib, io, json
from hyperframe.frame import Frame, HeadersFrame, ContinuationFrame, DataFrame, SettingsFrame
from hpack import Decoder

PKG = "com.ss.android.ugc.aweme"
SCRIPT = r"C:/Users/ADMINI~1/AppData/Local/Temp/claude/C--Users-Administrator/c2d58859-b20a-41fb-953d-f19fff254adc/scratchpad/cap_raw.js"
SECS = int(sys.argv[1]) if len(sys.argv) > 1 else 40
PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
FILTER = [s.lower() for s in sys.argv[2:] if s.lower() not in ("attach", "spawn")]   # optional host substrings

printed = 0
LIMIT = 200

def inflate(body, enc):
    # 无 content-encoding 头时,按魔数自动识别
    if not enc and body:
        if body[:4] == b"\x28\xb5\x2f\xfd": enc = "zstd"
        elif body[:2] == b"\x1f\x8b": enc = "gzip"
    try:
        if enc == "gzip": return gzip.decompress(body)
        if enc == "deflate":
            try: return zlib.decompress(body)
            except: return zlib.decompress(body, -zlib.MAX_WBITS)
        if enc == "br":
            import brotli; return brotli.decompress(body)
        if enc in ("zstd", "zst"):
            import zstandard
            try: return zstandard.ZstdDecompressor().decompress(body)
            except Exception:
                import io as _io
                return zstandard.ZstdDecompressor().stream_reader(_io.BytesIO(body)).read()
    except Exception:
        return None
    return body

class Dir:
    def __init__(self):
        self.buf = bytearray(); self.mode = None; self.dec = Decoder()
        self.hdr_acc = {}      # stream_id -> bytearray (header fragments)
        self.data_acc = {}     # stream_id -> bytearray

class Conn:
    def __init__(self): self.tx = Dir(); self.rx = Dir()

conns = {}
# stream_id -> request summary (for pairing with response)
reqinfo = {}

def hdr_list_to_map(hl):
    d = {}
    for k, v in hl:
        k = k.decode() if isinstance(k, bytes) else k
        v = v.decode() if isinstance(v, bytes) else v
        d.setdefault(k, v)
    return d

def want(host, path=""):
    if not FILTER: return True
    s = ((host or "") + " " + (path or "")).lower()
    return any(f in s for f in FILTER)

REQ_HDRS = ["user-agent", "cookie", "x-gorgon", "x-argus", "x-ladon", "x-khronos",
            "x-ss-stub", "x-tt-token", "content-type", "x-metasec-bind"]

from collections import Counter
HOSTS = Counter()

def emit_req(cid, sid, h):
    global printed
    host = h.get(":authority", "?"); path = h.get(":path", "?"); meth = h.get(":method", "?")
    HOSTS[host] += 1
    reqinfo[(cid, sid)] = (meth, host, path)
    if printed >= LIMIT or not want(host, path): return
    printed += 1
    print("\n>>> REQ  %s %s%s" % (meth, host, path))
    for k in REQ_HDRS:
        if k in h:
            v = h[k]
            print("    %s: %s" % (k, v[:160]))

def emit_resp(cid, sid, h, body):
    host = "?"; path = "?"; meth = "?"
    if (cid, sid) in reqinfo: meth, host, path = reqinfo[(cid, sid)]
    if not want(host, path): return
    global printed
    if printed >= LIMIT: return
    printed += 1
    status = h.get(":status", "?"); ct = h.get("content-type", "")
    if ct.startswith(("image/", "video/", "audio/", "font/")):
        printed -= 1; return  # skip media, keep the slot for real APIs
    print("\n<<< RESP %s  (%s %s%s)  %s" % (status, meth, host, path, ct))
    if body is None: print("    [no body]"); return
    dec = inflate(body, h.get("content-encoding", "").lower())
    if dec is None:
        print("    [body %d bytes, decode failed enc=%s]" % (len(body), h.get("content-encoding"))); return
    if any(t in ct for t in ("json", "text", "javascript", "xml")) or dec[:1] in (b"{", b"["):
        try: txt = dec.decode("utf-8", "replace")
        except: txt = repr(dec[:400])
        try:
            txt = json.dumps(json.loads(txt), ensure_ascii=False)  # normalize
        except Exception:
            pass
        print("    body[%d]: %s" % (len(dec), txt[:900].replace("\n", " ")))
    else:
        print("    [body %d bytes, %s]" % (len(dec), ct or "binary"))

def feed(cid, direction, data):
    conn = conns.setdefault(cid, Conn())
    D = conn.tx if direction == "TX" else conn.rx
    D.buf += data
    # classify
    if D.mode is None:
        if D.buf[:len(PREFACE)] == PREFACE:
            D.mode = "h2"; del D.buf[:len(PREFACE)]
        elif direction == "TX" and D.buf[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH"):
            D.mode = "h1"
        elif direction == "RX":
            # server side of h2 begins with a SETTINGS frame (type=4); assume h2 if plausible
            if len(D.buf) >= 9 and D.buf[3] == 0x04: D.mode = "h2"
            elif D.buf[:5] == b"HTTP/": D.mode = "h1"
        if D.mode is None: return
    if D.mode == "h1":
        return  # h1 text already human-readable; skip structured parse (rare on cronet)
    # h2 frame loop
    while len(D.buf) >= 9:
        try:
            fr, length = Frame.parse_frame_header(bytes(D.buf[:9]))
        except Exception:
            del D.buf[:1]; continue
        if len(D.buf) < 9 + length: break
        body = bytes(D.buf[9:9 + length]); del D.buf[:9 + length]
        try: fr.parse_body(memoryview(body))
        except Exception: continue
        sid = fr.stream_id
        if isinstance(fr, (HeadersFrame, ContinuationFrame)):
            D.hdr_acc.setdefault(sid, bytearray()).extend(fr.data)
            if 'END_HEADERS' in fr.flags:
                block = bytes(D.hdr_acc.pop(sid, b""))
                try: hl = D.dec.decode(block)
                except Exception: hl = None
                if hl is not None:
                    h = hdr_list_to_map(hl)
                    if direction == "TX": emit_req(cid, sid, h)
                    else: D.data_acc[sid] = (h, bytearray())  # stash resp headers, await body
            if isinstance(fr, HeadersFrame) and 'END_STREAM' in fr.flags and direction == "RX":
                hb = D.data_acc.pop(sid, None)
                if hb: emit_resp(cid, sid, hb[0], bytes(hb[1]))
        elif isinstance(fr, DataFrame):
            if direction == "RX" and sid in D.data_acc:
                D.data_acc[sid][1].extend(fr.data)
                if 'END_STREAM' in fr.flags:
                    h, b = D.data_acc.pop(sid); emit_resp(cid, sid, h, bytes(b))

def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg["payload"]
        if "info" in p: print("[*]", p["info"]); return
        if data: feed(p["c"], p["d"], data)
    elif msg.get("type") == "error":
        print("[error]", msg.get("stack") or msg.get("description"))

ATTACH = "attach" in [a.lower() for a in sys.argv]
dev = frida.get_usb_device(timeout=10)
if ATTACH:
    pid = int(subprocess.run("adb shell pidof " + PKG, shell=True,
              capture_output=True, text=True).stdout.strip().split()[0])
    print("[*] attaching to running pid", pid)
    s = dev.attach(pid)
else:
    subprocess.run("adb shell am force-stop " + PKG, shell=True, capture_output=True)
    pid = dev.spawn([PKG]); print("[*] spawned", pid); s = dev.attach(pid)
sc = s.create_script(open(SCRIPT, encoding="utf-8").read())
sc.on("message", on_message)
sc.set_log_handler(lambda l, t: print("[%s] %s" % (l, t)))
sc.load()
if not ATTACH: dev.resume(pid)
print("[*] capturing %ds (filter=%s, mode=%s). 现在请手动刷抖音!" % (SECS, FILTER or "ALL", "ATTACH" if ATTACH else "SPAWN"))
time.sleep(SECS)
print("\n[*] done. printed %d transactions." % printed)
print("\n===== 所有请求过的域名(host: 次数) =====")
for host, cnt in HOSTS.most_common(60):
    print("  %5d  %s" % (cnt, host))
