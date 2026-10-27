/*
 * unpin + raw TLS plaintext tap on libttboringssl.so
 * Sends every SSL_write(TX)/SSL_read(RX) buffer to Python, tagged by
 * connection (SSL* pointer) and direction, in call order. Python does
 * the HTTP/2 + HPACK + gzip/br decoding.
 */
const LIB = "libttboringssl.so";
let installed = false;
const ok = new NativeCallback(function () { return 0; }, "int", ["pointer", "pointer"]);
function ex(m, n) { try { return m.findExportByName(n); } catch (e) { return null; } }

function install() {
    const m = Process.findModuleByName(LIB);
    if (!m || installed) return !!m;
    installed = true;

    // --- unpin ---
    ["SSL_CTX_set_custom_verify", "SSL_set_custom_verify"].forEach(function (n) {
        const a = ex(m, n); if (a) Interceptor.attach(a, { onEnter: function (ar) { ar[2] = ok; } });
    });
    const gvr = ex(m, "SSL_get_verify_result");
    if (gvr) Interceptor.attach(gvr, { onLeave: function (r) { r.replace(0x0); } });

    // --- taps ---
    const w = ex(m, "SSL_write");
    if (w) Interceptor.attach(w, {
        onEnter: function (ar) {
            const n = ar[2].toInt32();
            if (n <= 0) return;
            try {
                send({ c: ar[0].toString(), d: "TX", n: n },
                     ar[1].readByteArray(n));
            } catch (e) {}
        }
    });
    const r = ex(m, "SSL_read");
    if (r) Interceptor.attach(r, {
        onEnter: function (ar) { this.c = ar[0].toString(); this.buf = ar[1]; },
        onLeave: function (ret) {
            const n = ret.toInt32();
            if (n <= 0) return;
            try {
                send({ c: this.c, d: "RX", n: n },
                     this.buf.readByteArray(n));
            } catch (e) {}
        }
    });
    send({ info: "unpin+tap installed on " + LIB });
    return true;
}

if (!install()) {
    let dl = null;
    try { dl = Module.getGlobalExportByName("android_dlopen_ext"); } catch (e) {}
    if (dl) Interceptor.attach(dl, {
        onEnter: function (a) { try { this.p = a[0].readCString(); } catch (e) {} },
        onLeave: function () { if (this.p && this.p.indexOf("libttboringssl") !== -1) install(); }
    });
}
