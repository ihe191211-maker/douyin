# 抖音 (com.ss.android.ugc.aweme) HTTPS 抓包 / 明文解码工具包

一套**自包含**的抖音流量解密方案:用 Frida 绕过 cronet 证书绑定并抓取 TLS 明文,
再用 Python 解 HTTP/2 + HPACK + gzip/zstd/br,直接还原成可读的请求 / JSON 响应。
**不依赖 ProxyPin / Charles / mitmproxy,不怕 QUIC,不吃版本偏移。**

实测环境:OnePlus 6 (Android 9, arm64) · Magisk + Zygisk · 抖音 40.6.0 · Frida 17.9.1

---

## 原理

```
抖音 h2/TLS ─[Frida hook libttboringssl.so]─→ 明文字节 ─→ Python 解码 ─→ 可读 REQ/RESP
             · unpin: SSL_CTX_set_custom_verify / SSL_set_custom_verify → 恒返回 ok
             ·        SSL_get_verify_result → 恒返回 0 (X509_V_OK)
             · tap:   SSL_write(请求明文) / SSL_read(响应明文)
```

关键点：
- 抖音自带 `libttboringssl.so`（字节魔改 BoringSSL）；`SSL_CTX_set_custom_verify` 等是**导出符号**，
  Frida 按名 hook（`Module.findExportByName`），**无需手动定位偏移**，升级版本也基本不失效。
- 抖音核心 API 默认走 **QUIC(UDP 443)**，`SSL_read/write` 只覆盖 TCP。必须**封 UDP 443**逼其回落 TCP 才抓得到 API。
- 图片走 TCP h2 所以一直能抓；业务 JSON 走 QUIC，封了才出来。

---

## 依赖

**PC 端**（已在 Python 3.12 验证）：
```
pip install frida-tools hyperframe hpack brotli zstandard
```
**设备端**：已 root（Magisk）+ Zygisk 开启；`frida-server`（版本需与 PC 的 frida 对齐）已推到 `/data/local/tmp/frida-server`。

> 下载 frida-server： https://github.com/frida/frida/releases → `frida-server-<版本>-android-arm64.xz`
> `xz -d` 解压后 `adb push` 到 `/data/local/tmp/frida-server`，`chmod 755`。

---

## 使用（三步）

```bash
# 1. 起 frida-server（重启手机后需重跑）
adb shell "su -c 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'"

# 2. 封 UDP443，逼 API 回落 TCP（抓业务接口必需；uid 换成你机器上抖音的 uid）
adb shell "su -c 'iptables  -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10120 -j REJECT; \
                  ip6tables -I OUTPUT -p udp --dport 443 -m owner --uid-owner 10120 -j REJECT'"

# 3. 手机上手动打开抖音、点过开屏进到信息流，然后在 PC 上抓：
python h2parse.py 120 attach normal          # 只看业务 API（*-normal-* 网关）
python h2parse.py 120 attach                  # 看全部（含图片/CDN）
python h2parse.py 120 attach comment user     # 只看含 comment/user 的接口
python h2parse.py 90  attach ZZZ              # 只做域名普查（打印所有请求过的 host）
```

参数：`h2parse.py <秒数> [attach] [过滤词...]`
- 不带 `attach` = spawn 全新实例（会卡开屏，不推荐；用 attach + 手动进 feed 最稳）。
- 过滤词匹配 host 或 path（大小写不敏感），多个为“或”。图片/视频响应自动跳过。

抖音的 uid 查法：`adb shell dumpsys package com.ss.android.ugc.aweme | grep userId=`

---

## 实时看板（推荐,浏览器实时看流量）

```bash
# 1) 起 frida-server + 封 UDP443(见上文;单封 UDP443 不影响抖音使用)
# 2) 手机上把抖音点到信息流
# 3) 启动看板(端口可自定;默认 8777,被占就换,如 8899)
python live_web.py 8899
# 4) 浏览器打开 http://127.0.0.1:8899 ,手机刷抖音即可实时看到
```
- 左侧实时滚动请求;点一条 → 右侧看完整 URL/请求头/解密 JSON body(自动解 gzip/zstd + JSON 美化)。
- 顶部过滤框输关键词(`amemv`/`webcast`/`comment`/`user`)只看该类;图片/视频自动过滤。
- 依赖 `dyparse.py`(公共解码模块)。停止:Ctrl+C。

## 文件说明

| 文件 | 作用 |
|---|---|
| `live_web.py` | **实时浏览器看板**(attach + unpin + 抓取 + 本地网页实时展示) |
| `dyparse.py` | 公共解码模块(HTTP/2 + HPACK + gzip/zstd/br),`live_web.py` 依赖它 |
| `h2parse.py` | 批处理版:spawn/attach + 收明文 + 解码 + 打印 + 域名统计(定时窗口) |
| `dy_unpin.js` | 纯 unpin 脚本(只绕过证书绑定,配任意抓包工具:`frida -U -f com.ss.android.ugc.aweme -l dy_unpin.js`) |
| `cap_raw.js` | unpin + 把 SSL_read/write 明文字节送到 Python(供 live_web.py / h2parse.py 用) |
| `capture.sh` / `cleanup.sh` | 一键起环境(封 UDP443)/ 一键恢复网络 |
| `sample_capture.txt` | 一份真实抓取样例(含 webcast API、roma.config.json 等,供参考) |

> **关于推给 Yakit**:试过用 iptables 把抖音 443 全量 DNAT 到 Yakit(透明劫持),
> 会因为 Yakit 未正确转发透明连接 + 全量 MITM 过重,导致抖音"网络错误"无法加载。
> 抖音对全量 MITM 很敏感,**推荐用本工具(Frida 直接解,不碰网络路径)**,稳定且不会弄挂 App。
> 若坚持 Yakit,需在 Yakit 开启"透明劫持"模式,且可能仍不稳定。

---

## 注意 / 清理

- **UDP443 封锁会影响正常上网**（抖音用不了 QUIC）。抓完恢复：
  ```bash
  adb shell "su -c 'iptables  -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10120 -j REJECT; \
                    ip6tables -D OUTPUT -p udp --dport 443 -m owner --uid-owner 10120 -j REJECT'"
  ```
- **必须用 attach + 手动进 feed**：抖音一进程新建就卡开屏（有隐私弹窗/开屏广告要手点），
  盲点容易点到广告跳浏览器。让 app 进到信息流再 attach，新连接能干净解码。
- 只能解到 **HTTP 层明文**；请求头里的 `X-Gorgon/X-Argus`、URL 里的 `r_signature` 是应用层签名，
  能看不能直接伪造——要伪造得再逆 `libmetasec_ml.so`（另一个工程）。

---

## 抓取中出现的 P2P/CDN 相关域名（备注，非结论）

抓包里出现过这些带 P2P 特征的域名：
- `seeds-open.comfylink.com/api/sdk/get_seeds`、`sd-gl.comfylink.com/psdk/getseeds_v3`
- `douyinve.starrydyn.com/edge/tracker/v3/announce`（tracker announce）
- `*.manlaxycloud.com:16718`、`*.qtaeixd.com:60136`（随机长子域 + 非标高端口）

`seeds/tracker/announce` 是 **P2P-CDN（peer 辅助的视频分发）**的典型特征，很可能就是抖音自带的
P2P-CDN SDK 在拉取 peer 节点分发视频——属于视频类 App 的常见行为，**不能据此判定异常**。
如需确认，可对这些域名做专门排查。

> 更正：`com.network.proxy`（监听 `0.0.0.0:9099`）是 **ProxyPin 抓包工具本身**（其 Android 包名即
> `com.network.proxy`，9099 为其默认代理端口），并非可疑代理 SDK。此前的相关推断作废。
