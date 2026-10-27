# -*- coding: utf-8 -*-
"""抖音流量实时看板。
  1) adb shell 起 frida-server;建议先封 UDP443(见 capture.sh / README)
  2) 手机上把抖音点到信息流
  3) python live_web.py           # 然后浏览器打开 http://127.0.0.1:8777
参数: python live_web.py [port] [过滤词...]   过滤词匹配 host/path,留空=全部
"""
import frida, sys, os, json, threading, queue, subprocess, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from dyparse import Parser

PKG = "com.ss.android.ugc.aweme"
HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8777
FILTER = [a.lower() for a in sys.argv[2:]]
SKIP_MEDIA = True

subs = []            # SSE 订阅者队列
subs_lock = threading.Lock()
seq = 0

def want(host, path):
    if not FILTER: return True
    s = ((host or "") + " " + (path or "")).lower()
    return any(f in s for f in FILTER)

def push(obj):
    global seq
    seq += 1; obj["seq"] = seq; obj["t"] = time.strftime("%H:%M:%S")
    data = json.dumps(obj, ensure_ascii=False)
    with subs_lock:
        for q in list(subs):
            try: q.put_nowait(data)
            except Exception: pass

def on_txn(tx):
    if not want(tx.get("host"), tx.get("path")): return
    if tx["type"] == "resp" and SKIP_MEDIA and tx.get("ct", "").startswith(("image/", "video/", "audio/", "font/")):
        return
    # 精简 headers + 截断 body
    hdr = {k: v for k, v in tx.get("headers", {}).items()}
    body = tx.get("body")
    if body and len(body) > 40000: body = body[:40000] + "\n...[截断]"
    push({"type": tx["type"], "method": tx.get("method"), "status": tx.get("status"),
          "host": tx.get("host"), "path": tx.get("path"), "ct": tx.get("ct", ""),
          "blen": tx.get("blen", 0), "headers": hdr, "body": body})

parser = Parser(on_txn)

# ---------- HTTP ----------
PAGE = """<!doctype html><html lang=zh><head><meta charset=utf-8>
<title>抖音流量实时看板</title><style>
:root{--bg:#0f1420;--pnl:#161c2b;--line:#232c40;--fg:#e6e9f0;--mut:#8a93a6;--g:#4ade80;--r:#f87171;--b:#60a5fa;--y:#fbbf24}
*{box-sizing:border-box}body{margin:0;font:13px/1.5 system-ui,"Microsoft YaHei",sans-serif;background:var(--bg);color:var(--fg);height:100vh;display:flex;flex-direction:column}
header{padding:8px 14px;background:var(--pnl);border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}
header b{color:var(--b)} #stat{color:var(--mut)} input{background:#0d121e;border:1px solid var(--line);color:var(--fg);padding:5px 8px;border-radius:6px;width:220px}
button{background:#26304a;color:var(--fg);border:1px solid var(--line);padding:5px 10px;border-radius:6px;cursor:pointer}
main{flex:1;display:flex;min-height:0}
#list{width:52%;overflow:auto;border-right:1px solid var(--line)}
table{width:100%;border-collapse:collapse}td{padding:4px 8px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:1px}
tr{cursor:pointer}tr:hover{background:#1b2334}tr.sel{background:#24304a}
.m{color:var(--y);font-weight:600}.h{color:var(--b)}.p{color:var(--fg)}.s2{color:var(--g)}.s4,.s5{color:var(--r)}
#detail{flex:1;overflow:auto;padding:12px 14px}#detail h3{margin:10px 0 4px;color:var(--b);font-size:12px}
pre{white-space:pre-wrap;word-break:break-all;background:#0d121e;border:1px solid var(--line);border-radius:6px;padding:10px;margin:0}
.mut{color:var(--mut)}
</style></head><body>
<header><b>抖音流量实时看板</b><span id=stat>连接中…</span>
<input id=flt placeholder="前端过滤 host/path"><button onclick=clr()>清空</button>
<label class=mut><input type=checkbox id=auto checked style=width:auto> 自动滚动</label></header>
<main><div id=list><table><tbody id=rows></tbody></table></div><div id=detail class=mut>点左侧一条查看详情</div></main>
<script>
let items=[],sel=-1;
const rows=document.getElementById('rows'),stat=document.getElementById('stat'),flt=document.getElementById('flt'),detail=document.getElementById('detail');
function scls(s){s=(''+s)[0];return s=='2'?'s2':(s=='4'||s=='5')?'s4':''}
function render(){const f=flt.value.toLowerCase();rows.innerHTML='';items.forEach((o,i)=>{
 if(f&&!((o.host+o.path).toLowerCase().includes(f)))return;
 const tr=document.createElement('tr');if(i==sel)tr.className='sel';
 const st=o.type=='resp'?`<span class=${scls(o.status)}>${o.status}</span>`:'<span class=mut>·</span>';
 tr.innerHTML=`<td class=mut>${o.t}</td><td class=m>${o.method||''}</td><td>${st}</td><td class=h>${o.host||''}</td><td class=p>${(o.path||'').split('?')[0]}</td>`;
 tr.onclick=()=>{sel=i;show(o);render()};rows.appendChild(tr);});
 if(document.getElementById('auto').checked){const l=document.getElementById('list');l.scrollTop=l.scrollHeight;}}
function show(o){let h='';h+=`<h3>${o.method||''} ${o.host}${o.path}</h3>`;
 if(o.type=='resp')h+=`<div class=mut>status ${o.status} · ${o.ct} · ${o.blen} bytes</div>`;
 h+='<h3>Headers</h3><pre>'+esc(Object.entries(o.headers||{}).map(([k,v])=>k+': '+v).join('\\n'))+'</pre>';
 if(o.body!=null){let b=o.body;try{b=JSON.stringify(JSON.parse(b),null,2)}catch(e){}h+='<h3>Body</h3><pre>'+esc(b)+'</pre>';}
 else if(o.type=='resp')h+='<h3>Body</h3><pre class=mut>[二进制/无 body]</pre>';
 detail.className='';detail.innerHTML=h;}
function esc(s){return (s||'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
function clr(){items=[];sel=-1;render();detail.innerHTML='已清空';detail.className='mut'}
flt.oninput=render;
const es=new EventSource('/events');
es.onopen=()=>stat.textContent='已连接 ✓ 实时接收中';
es.onerror=()=>stat.textContent='连接断开(脚本可能已停)';
es.onmessage=e=>{items.push(JSON.parse(e.data));if(items.length>2000)items.shift();render();stat.textContent='已连接 ✓  '+items.length+' 条';};
</script></body></html>"""

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path == "/":
            b = PAGE.encode("utf-8")
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        elif self.path == "/events":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache"); self.send_header("Connection", "keep-alive")
            self.end_headers()
            q = queue.Queue(maxsize=5000)
            with subs_lock: subs.append(q)
            try:
                while True:
                    try: data = q.get(timeout=15)
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n"); self.wfile.flush(); continue
                    self.wfile.write(b"data: " + data.encode("utf-8") + b"\n\n"); self.wfile.flush()
            except Exception:
                pass
            finally:
                with subs_lock:
                    if q in subs: subs.remove(q)
        else:
            self.send_response(404); self.end_headers()

def serve():
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    print("[*] 看板已启动:  http://127.0.0.1:%d   (Ctrl+C 停止)" % PORT)
    httpd.serve_forever()

# ---------- Frida ----------
def on_message(msg, data):
    if msg.get("type") == "send":
        p = msg["payload"]
        if "info" in p: print("[*]", p["info"]); return
        if data: parser.feed(p["c"], p["d"], data)
    elif msg.get("type") == "error":
        print("[frida-error]", msg.get("stack") or msg.get("description"))

def main():
    threading.Thread(target=serve, daemon=True).start()
    serial = os.environ.get("ADB_SERIAL", "")
    adb_pfx = ("adb -s " + serial + " ") if serial else "adb "
    pid = int(subprocess.run(adb_pfx + "shell pidof " + PKG, shell=True,
              capture_output=True, text=True).stdout.strip().split()[0])
    print("[*] attach 抖音 pid", pid)
    fdev = os.environ.get("FRIDA_DEVICE", "")
    dev = frida.get_device(fdev, timeout=10) if fdev else frida.get_usb_device(timeout=10)
    s = dev.attach(pid)
    sc = s.create_script(open(os.path.join(HERE, "cap_raw.js"), encoding="utf-8").read())
    sc.on("message", on_message)
    sc.load()
    print("[*] 抓取中,浏览器打开 http://127.0.0.1:%d ,在手机上刷抖音即可实时看到。" % PORT)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] 结束。")

if __name__ == "__main__":
    main()
