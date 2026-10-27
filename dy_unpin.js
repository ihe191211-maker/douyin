/*
 * Douyin (com.ss.android.ugc.aweme) cronet/ttboringssl SSL Pinning bypass
 * Target: libttboringssl.so (ByteDance's BoringSSL fork)
 * Method: take over BoringSSL custom_verify callback -> force ssl_verify_ok(0),
 *         and override SSL_get_verify_result -> X509_V_OK(0).
 * Frida 17 API compatible. Hooks by exported symbol name (no offsets).
 */

const LIB = "libttboringssl.so";
const SSL_VERIFY_OK = 0;

const okCallback = new NativeCallback(function (ssl, out_alert) {
    return SSL_VERIFY_OK;
}, "int", ["pointer", "pointer"]);

function modExport(mod, name) {
    // mod: Module instance
    try { return mod.findExportByName(name); } catch (e) { return null; }
}

function hookCustomVerify(mod, name) {
    const addr = modExport(mod, name);
    if (!addr) { console.log("[!] not found: " + name); return; }
    Interceptor.attach(addr, {
        onEnter: function (args) { args[2] = okCallback; }  // replace callback ptr
    });
    console.log("[+] hooked " + name + " @ " + addr);
}

function hookGetVerifyResult(mod) {
    const addr = modExport(mod, "SSL_get_verify_result");
    if (!addr) { console.log("[!] not found: SSL_get_verify_result"); return; }
    Interceptor.attach(addr, {
        onLeave: function (retval) { retval.replace(0x0); }  // X509_V_OK
    });
    console.log("[+] hooked SSL_get_verify_result @ " + addr);
}

function install() {
    const mod = Process.findModuleByName(LIB);
    if (!mod) return false;
    hookCustomVerify(mod, "SSL_CTX_set_custom_verify");
    hookCustomVerify(mod, "SSL_set_custom_verify");
    hookGetVerifyResult(mod);
    console.log("[*] " + LIB + " unpin installed");
    return true;
}

if (!install()) {
    console.log("[*] " + LIB + " not loaded yet, watching dlopen ...");
    let dlopen = null;
    try { dlopen = Module.getGlobalExportByName("android_dlopen_ext"); } catch (e) {}
    if (!dlopen) { try { dlopen = Module.getGlobalExportByName("dlopen"); } catch (e) {} }
    if (!dlopen) { console.log("[!] cannot resolve dlopen"); }
    else {
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
            },
            onLeave: function () {
                if (this.path && this.path.indexOf("libttboringssl") !== -1) {
                    install();
                }
            }
        });
    }
}
