# -*- coding: utf-8 -*-
"""抖音 TLS 明文 -> HTTP/2 + HPACK + gzip/zstd/br 解码,公共模块。
用法: p = Parser(on_txn); p.feed(conn_id, "TX"/"RX", raw_bytes)
      on_txn(dict) 在每个请求/响应解出后回调。"""
import gzip, zlib, io
from hyperframe.frame import Frame, HeadersFrame, ContinuationFrame, DataFrame
from hpack import Decoder

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def inflate(body, enc):
    if not enc and body:
        if body[:4] == b"\x28\xb5\x2f\xfd": enc = "zstd"
        elif body[:2] == b"\x1f\x8b": enc = "gzip"
    try:
        if enc == "gzip": return gzip.decompress(body)
        if enc == "deflate":
            try: return zlib.decompress(body)
            except Exception: return zlib.decompress(body, -zlib.MAX_WBITS)
        if enc == "br":
            import brotli; return brotli.decompress(body)
        if enc in ("zstd", "zst"):
            import zstandard
            try: return zstandard.ZstdDecompressor().decompress(body)
            except Exception:
                return zstandard.ZstdDecompressor().stream_reader(io.BytesIO(body)).read()
    except Exception:
        return None
    return body

def body_to_text(dec, ct):
    if dec is None: return None
    if any(t in ct for t in ("json", "text", "javascript", "xml")) or dec[:1] in (b"{", b"["):
        try: return dec.decode("utf-8", "replace")
        except Exception: return repr(dec[:2000])
    return None  # 二进制(图片/视频等)

class _Dir:
    def __init__(self):
        self.buf = bytearray(); self.mode = None; self.dec = Decoder()
        self.hdr = {}; self.data = {}

class _Conn:
    def __init__(self): self.tx = _Dir(); self.rx = _Dir()

def _hmap(hl):
    d = {}
    for k, v in hl:
        k = k.decode() if isinstance(k, bytes) else k
        v = v.decode() if isinstance(v, bytes) else v
        d.setdefault(k, v)
    return d

class Parser:
    def __init__(self, on_txn):
        self.on_txn = on_txn
        self.conns = {}
        self.reqinfo = {}

    def feed(self, cid, direction, data):
        conn = self.conns.setdefault(cid, _Conn())
        D = conn.tx if direction == "TX" else conn.rx
        D.buf += data
        if D.mode is None:
            if D.buf[:len(PREFACE)] == PREFACE:
                D.mode = "h2"; del D.buf[:len(PREFACE)]
            elif direction == "TX" and D.buf[:8].split(b" ")[0] in \
                 (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"OPTIONS", b"PATCH"):
                D.mode = "h1"
            elif direction == "RX":
                if len(D.buf) >= 9 and D.buf[3] == 0x04: D.mode = "h2"
                elif D.buf[:5] == b"HTTP/": D.mode = "h1"
            if D.mode is None: return
        if D.mode == "h1": return
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
                D.hdr.setdefault(sid, bytearray()).extend(fr.data)
                if 'END_HEADERS' in fr.flags:
                    block = bytes(D.hdr.pop(sid, b""))
                    try: h = _hmap(D.dec.decode(block))
                    except Exception: h = None
                    if h is not None:
                        if direction == "TX": self._req(cid, sid, h)
                        else: D.data[sid] = (h, bytearray())
                if isinstance(fr, HeadersFrame) and 'END_STREAM' in fr.flags and direction == "RX":
                    hb = D.data.pop(sid, None)
                    if hb: self._resp(cid, sid, hb[0], bytes(hb[1]))
            elif isinstance(fr, DataFrame):
                if direction == "RX" and sid in D.data:
                    D.data[sid][1].extend(fr.data)
                    if 'END_STREAM' in fr.flags:
                        h, b = D.data.pop(sid); self._resp(cid, sid, h, bytes(b))

    def _req(self, cid, sid, h):
        host = h.get(":authority", "?"); path = h.get(":path", "?"); meth = h.get(":method", "?")
        self.reqinfo[(cid, sid)] = (meth, host, path)
        self.on_txn({"type": "req", "cid": cid, "sid": sid, "method": meth,
                     "host": host, "path": path, "headers": h})

    def _resp(self, cid, sid, h, body):
        meth = host = path = "?"
        if (cid, sid) in self.reqinfo: meth, host, path = self.reqinfo[(cid, sid)]
        ct = h.get("content-type", "")
        dec = inflate(body, h.get("content-encoding", "").lower()) if body else None
        txt = body_to_text(dec, ct) if dec is not None else None
        self.on_txn({"type": "resp", "cid": cid, "sid": sid, "status": h.get(":status", "?"),
                     "method": meth, "host": host, "path": path, "ct": ct, "headers": h,
                     "blen": len(dec) if dec is not None else 0, "body": txt})
