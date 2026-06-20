var fopen = Module.findExportByName("libc.so", "fopen");
if (fopen) {
    Interceptor.attach(fopen, {
        onEnter: function(args) {
            try {
                var path = Memory.readCString(args[0]);
                if (path && (
                    path.indexOf("magisk") >= 0 ||
                    path.indexOf("frida") >= 0 ||
                    path.indexOf("/su") >= 0 ||
                    path.indexOf("busybox") >= 0
                )) {
                    Memory.writeUtf8String(args[0], "/notexists");
                }
            } catch(e) {}
        }
    });
}
try {
    var sysprop = Module.findExportByName("libc.so", "__system_property_get");
    Interceptor.attach(sysprop, {
        onEnter: function(args) {
            this.key = args[0].readCString();
            this.ret = args[1];
        },
        onLeave: function(ret) {
            var fake = {
                "service.adb.root": "0",
                "ro.debuggable": "0",
                "ro.secure": "1",
                "ro.kernel.qemu": "0",
                "ro.build.tags": "release-keys",
                "ro.build.type": "user",
            };
            if (this.key && fake[this.key]) {
                var p = Memory.allocUtf8String(fake[this.key]);
                Memory.copy(this.ret, p, fake[this.key].length + 1);
            }
        }
    });
} catch(e) {}
// ==============================
// HOOK ALL SSL LIBRARIES
// Targets: libssl.so, libflutter.so,
// libpolarssl.so, libclib.so, libtmlib.so
// ==============================
function hookAllSSL() {
    var targets = [
        "libssl.so", "libflutter.so", "libpolarssl.so",
        "libclib.so", "libtmlib.so", "libsecurity.so",
        "libjavacrypto.so"
    ];
    var keywords = [
        "Hash", "LoginRequest", "SplashRequest",
        "JwtToken", "glproducts", "docker.mactech",
        "UserId", "Password", "responseCode"
    ];
    targets.forEach(function(lib) {
        try {
            // SSL_write variants
            ["SSL_write", "ssl_write", "mbedtls_ssl_write",
             "ssl3_write", "tls1_write"].forEach(function(sym) {
                try {
                    var addr = Module.findExportByName(lib, sym);
                    if (addr) {
                        console.log("[+] " + sym + " found in " + lib);
                        Interceptor.attach(addr, {
                            onEnter: function(args) {
                                try {
                                    var len = args[2].toInt32();
                                    if (len <= 0 || len > 65536) return;
                                    var data = Memory.readUtf8String(args[1], Math.min(len, 4096));
                                    if (!data) return;
                                    var found = false;
                                    for (var i = 0; i < keywords.length; i++) {
                                        if (data.indexOf(keywords[i]) >= 0) { found = true; break; }
                                    }
                                    if (found) {
                                        console.log("\n===== [" + lib + "] OUTGOING =====");
                                        console.log(data);
                                        console.log("================================\n");
                                    }
                                } catch(e) {}
                            }
                        });
                    }
                } catch(e) {}
            });
            // SSL_read variants
            ["SSL_read", "ssl_read", "mbedtls_ssl_read"].forEach(function(sym) {
                try {
                    var addr = Module.findExportByName(lib, sym);
                    if (addr) {
                        Interceptor.attach(addr, {
                            onEnter: function(args) { this.buf = args[1]; },
                            onLeave: function(ret) {
                                try {
                                    var n = ret.toInt32();
                                    if (n <= 0 || n > 65536) return;
                                    var data = Memory.readUtf8String(this.buf, Math.min(n, 4096));
                                    if (!data) return;
                                    var found = false;
                                    for (var i = 0; i < keywords.length; i++) {
                                        if (data.indexOf(keywords[i]) >= 0) { found = true; break; }
                                    }
                                    if (found) {
                                        console.log("\n===== [" + lib + "] INCOMING =====");
                                        console.log(data);
                                        console.log("================================\n");
                                    }
                                } catch(e) {}
                            }
                        });
                    }
                } catch(e) {}
            });
        } catch(e) {}
    });
    console.log("[+] All SSL libraries hooked!");
}
// ==============================
// HOOK libclib.so DIRECTLY
// Talsec's main RASP library
// ==============================
function hookLibclib() {
    try {
        var clib = Process.findModuleByName("libclib.so");
        if (!clib) {
            setTimeout(hookLibclib, 1000);
            return;
        }
        console.log("[+] libclib.so found at: " + clib.base);
        // List all exports
        var exports = Module.enumerateExports("libclib.so");
        exports.forEach(function(e) {
            try {
                if (e.name.toLowerCase().indexOf("ssl") >= 0 ||
                    e.name.toLowerCase().indexOf("write") >= 0 ||
                    e.name.toLowerCase().indexOf("send") >= 0 ||
                    e.name.toLowerCase().indexOf("check") >= 0 ||
                    e.name.toLowerCase().indexOf("root") >= 0 ||
                    e.name.toLowerCase().indexOf("detect") >= 0) {
                    console.log("[libclib export] " + e.name + " @ " + e.address);
                }
            } catch(ex) {}
        });
        // Hook ALL exports in libclib to find security checks
        exports.forEach(function(e) {
            try {
                if (e.type === "function") {
                    Interceptor.attach(e.address, {
                        onLeave: function(retval) {
                            // If returns 1/true (detected), change to 0/false
                            try {
                                if (retval.toInt32() === 1) {
                                    retval.replace(0);
                                }
                            } catch(ex) {}
                        }
                    });
                }
            } catch(ex) {}
        });
        console.log("[+] libclib.so all exports hooked!");
    } catch(e) {
        console.log("[-] libclib: " + e);
    }
}
// ==============================
// ALL JAVA BYPASSES
// ==============================
setImmediate(function() {
    Java.perform(function() {
        // Build props
        try {
            var Build = Java.use("android.os.Build");
            Build.PRODUCT.value      = "gracerltexx";
            Build.MANUFACTURER.value = "samsung";
            Build.BRAND.value        = "samsung";
            Build.DEVICE.value       = "gracerlte";
            Build.MODEL.value        = "SM-N935F";
            Build.HARDWARE.value     = "samsungexynos8890";
            Build.FINGERPRINT.value  = "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";
            Build.TAGS.value         = "release-keys";
            Build.TYPE.value         = "user";
            console.log("[+] Build spoofed");
        } catch(e) {}
        // File.exists
        try {
            var NativeFile = Java.use("java.io.File");
            NativeFile.exists.implementation = function() {
                var p = this.getAbsolutePath();
                if (p.indexOf("magisk") >= 0 || p.indexOf("frida") >= 0 ||
                    p === "/system/bin/su" || p === "/system/xbin/su" ||
                    p === "/sbin/su" || p === "/su/bin/su" ||
                    p === "/system/app/Superuser.apk" ||
                    p === "/system/xbin/busybox") return false;
                return this.exists();
            };
        } catch(e) {}
        // Runtime.exec
        try {
            var exec1 = Java.use("java.lang.Runtime").exec.overload("java.lang.String");
            exec1.implementation = function(cmd) {
                if (cmd.indexOf("su") >= 0 || cmd.indexOf("getprop") >= 0)
                    return exec1.call(this, "grep");
                return exec1.call(this, cmd);
            };
        } catch(e) {}
        // PackageManager
        try {
            var rootApps = ["com.topjohnwu.magisk","eu.chainfire.supersu","me.weishu.kernelsu"];
            var PM = Java.use("android.app.ApplicationPackageManager");
            PM.getPackageInfo.overload("java.lang.String","int").implementation = function(p,f) {
                if (rootApps.indexOf(p) > -1) p = "fake.not.found";
                return this.getPackageInfo.overload("java.lang.String","int").call(this,p,f);
            };
        } catch(e) {}
        // Block Talsec threat listener
        try {
            var ThreatListener = Java.use("com.aheaditec.talsec_security.security.api.ThreatListener");
            ThreatListener.threatDetected.implementation = function(threat) {
                console.log("[+] Blocked ThreatListener: " + threat);
            };
            console.log("[+] ThreatListener blocked!");
        } catch(e) { console.log("[-] ThreatListener: " + e); }
        // Block Talsec SDK start
        try {
            var TalsecApi = Java.use("com.aheaditec.talsec_security.security.api.Talsec");
            TalsecApi.start.overload(
                "android.app.Application",
                "com.aheaditec.talsec_security.security.api.TalsecConfig"
            ).implementation = function(app, config) {
                console.log("[+] Blocked Talsec.start()!");
            };
        } catch(e) { console.log("[-] Talsec.start: " + e); }
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.implementation = function(a,b,c,d,e,f) { return a; };
            console.log("[+] TrustManagerImpl bypassed");
        } catch(e) {}
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            CertPinner.check.overload("java.lang.String","java.util.List").implementation = function(h,c) {
                console.log("[SSL] CertPinner bypassed: " + h);
            };
        } catch(e) {}
        try {
            var OpenSSL = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
            OpenSSL.verifyCertificateChain.implementation = function(a,b) {};
        } catch(e) {}
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function(v,h,e) { h.proceed(); };
        } catch(e) {}
        // Block DNS for Talsec
        try {
            var InetAddress = Java.use("java.net.InetAddress");
            InetAddress.getAllByName.implementation = function(host) {
                if (host && (host.indexOf("talsec") >= 0 || host.indexOf("approtect") >= 0)) {
                    console.log("[+] Blocked Talsec DNS: " + host);
                    return InetAddress.getAllByName("127.0.0.1");
                }
                return this.getAllByName(host);
            };
        } catch(e) {}
        console.log("[+] All Java hooks done.");
    });
});
// ==============================
// TALSEC NATIVE BYPASS
// ==============================
function hookTalsec() {
    Java.perform(function() {
        try {
            var TalsecApiNatives = Java.use("com.aheaditec.talsec_security.security.api.Natives");
            TalsecApiNatives.start.implementation = function(ctx, z) {
                console.log("[+] BLOCKED Talsec.Natives.start!");
            };
        } catch(e) {
            setTimeout(hookTalsec, 300);
            return;
        }
        try {
            var TN = Java.use("com.aheaditec.talsec_security.security.Natives");
            TN.k.implementation  = function() { return false; };
            TN.j.overload().implementation = function() { return false; };
            TN.o.implementation  = function() { return false; };
            TN.i.overload().implementation = function() { return Java.array('int',[]); };
            TN.c.implementation  = function(a) { return false; };
            console.log("[+] Talsec Natives bypassed!");
        } catch(e) {}
        try { Java.use("S0.g").k.implementation = function(a,b) {}; } catch(e) {}
        try { Java.use("T0.Z").a.implementation = function() { return false; }; } catch(e) {}
    });
}
setTimeout(hookTalsec, 500);
// App root checks
function hookAppClasses() {
    Java.perform(function() {
        try {
            var A = Java.use("w2.AbstractC1042c");
            ["l","k","m","c","f","e","g","b","j","d"].forEach(function(m) {
                try { A[m].implementation = function() { return false; }; } catch(e) {}
            });
            console.log("[+] AbstractC1042c bypassed!");
        } catch(e) {
            setTimeout(hookAppClasses, 300);
            return;
        }
        try {
            var B = Java.use("l2.C0771b");
            ["n","o","f","g","d","l","c","e"].forEach(function(m) {
                try { B[m].implementation = function() { return false; }; } catch(e) {}
            });
            try { B.b.implementation = function(s) { return false; }; } catch(e) {}
        } catch(e) {}
        try {
            var C = Java.use("r2.C0922c");
            C.e.implementation = function(i,d) {
                var method = i.f2649a.value;
                if (method === "isJailBroken")           { d.a(Java.use("java.lang.Boolean").valueOf(false)); return; }
                if (method === "isRealDevice")            { d.a(Java.use("java.lang.Boolean").valueOf(true));  return; }
                if (method === "isDevelopmentModeEnable") { d.a(Java.use("java.lang.Boolean").valueOf(false)); return; }
                if (method === "usbDebuggingCheck")       { d.a(Java.use("java.lang.Boolean").valueOf(false)); return; }
                return this.e(i,d);
            };
        } catch(e) {}
        console.log("[+] App root checks bypassed!");
    });
}
setTimeout(hookAppClasses, 1000);
// Start SSL hooks after 2 seconds
setTimeout(hookAllSSL, 2000);
// Start libclib hooks after 3 seconds
setTimeout(hookLibclib, 3000);
console.log("[+] FINALBYPASS_V4 loaded!");
