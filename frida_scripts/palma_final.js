var _allTrustInstance = null;
function getAllTrust() {
    if (_allTrustInstance) return _allTrustInstance;
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var AllTrust = Java.registerClass({
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function (chain, authType) {},
            checkServerTrusted: function (chain, authType) {
                console.log("[+] checkServerTrusted bypassed");
            },
            getAcceptedIssuers: function () { return []; }
        }
    });
    _allTrustInstance = AllTrust.$new();
    return _allTrustInstance;
}
Java.perform(function () {
    try {
        Java.use("android.os.Build").PRODUCT.value      = "gracerltexx";
        Java.use("android.os.Build").MANUFACTURER.value = "samsung";
        Java.use("android.os.Build").BRAND.value        = "samsung";
        Java.use("android.os.Build").DEVICE.value       = "gracerlte";
        Java.use("android.os.Build").MODEL.value        = "SM-N935F";
        Java.use("android.os.Build").HARDWARE.value     = "samsungexynos8890";
        Java.use("android.os.Build").FINGERPRINT.value  =
            "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";
        Java.use("android.os.Build").TAGS.value         = "release-keys";
        console.log("[+] Build fingerprint spoofed");
    } catch (e) { console.log("[-] Build spoof: " + e); }
    // ── BLOCK 2: b3.a.m() — Custom integrity check (from v3) ────
    // Replaces failed c3.a.u() — confirmed via JADX
    try {
        var b3a = Java.use("b3.a");
        b3a.m.overload("android.content.Context").implementation = function (ctx) {
            console.log("[+] b3.a.m(Context) blocked — integrity check bypassed");
            return false;
        };
        try { b3a.m.overload().implementation = function () { return false; }; } catch(e) {}
        console.log("[+] b3.a.m() hooked");
    } catch (e) { console.log("[-] b3.a.m(): " + e); }
    // ── BLOCK 3: RootBeer (confirmed in JADX screenshot) ─────────
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () { return false; };
        RootBeer.isRootedWithBusyBoxCheck.implementation = function () { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () { return false; };
        RootBeer.detectRootManagementApps.implementation = function () { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation = function () { return false; };
        RootBeer.checkForBinary.implementation = function (b) { return false; };
        console.log("[+] RootBeer fully bypassed");
    } catch (e) { console.log("[-] RootBeer: " + e); }
    // ── BLOCK 4: Firebase Crashlytics isRooted (from JADX) ───────
    try {
        var CommonUtils = Java.use(
            "com.google.firebase.crashlytics.internal.common.CommonUtils"
        );
        CommonUtils.isRooted.overload("android.content.Context").implementation = function (ctx) {
            console.log("[+] Crashlytics CommonUtils.isRooted() → false");
            return false;
        };
        console.log("[+] Crashlytics isRooted() hooked");
    } catch (e) { console.log("[-] Crashlytics CommonUtils: " + e); }
    // ── BLOCK 5: USB Debugging check ─────────────────────────────
    try {
        var SecureSettings = Java.use("android.provider.Settings$Secure");
        SecureSettings.getInt.overload(
            "android.content.ContentResolver",
            "java.lang.String",
            "int"
        ).implementation = function (resolver, key, def) {
            if (key === "development_settings_enabled" || key === "adb_enabled") {
                console.log("[+] Settings.Secure blocked: " + key);
                return 0;
            }
            return this.getInt(resolver, key, def);
        };
        console.log("[+] USB debugging check bypassed");
    } catch (e) { console.log("[-] Settings.Secure: " + e); }
    // ── BLOCK 6: System.exit() safety net ────────────────────────
    try {
        var System = Java.use("java.lang.System");
        System.exit.implementation = function (code) {
            console.log("[!] System.exit(" + code + ") blocked");
        };
        console.log("[+] System.exit() neutralized");
    } catch (e) { console.log("[-] System.exit: " + e); }
    // ── BLOCK 7: finishAffinity safety net ───────────────────────
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.finishAffinity.implementation = function () {
            console.log("[!] finishAffinity() blocked");
        };
        console.log("[+] finishAffinity() neutralized");
    } catch (e) { console.log("[-] finishAffinity: " + e); }
    // ── BLOCK 8: MotionEvent flag bypass ─────────────────────────
    try {
        var MotionEvent = Java.use("android.view.MotionEvent");
        MotionEvent.getFlags.implementation = function () { return 0; };
        console.log("[+] MotionEvent.getFlags() bypassed");
    } catch (e) { console.log("[-] MotionEvent: " + e); }
    console.log("[+] All root/integrity hooks applied");
});
// ── SSL UNPINNING (delayed — after app initialises) ───────────────
setTimeout(function () {
    Java.perform(function () {
        console.log("[+] Applying SSL Unpinning...");
        // FIXED: don't touch trustManagers/delegate fields directly
        // Instead hook SSLContext before TLSSocketFactory uses it
        try {
            TLSSocketFactory.$init.implementation = function () {
                console.log("[+] TLSSocketFactory.$init hooked");
                var SSLCtx = Java.use("javax.net.ssl.SSLContext").getInstance("TLSv1.2");
                SSLCtx.init(null, [getAllTrust()], null);
                // Call original but SSLContext is already poisoned
                this.$init();
            };
            console.log("[+] TLSSocketFactory hooked");
        } catch (e) { console.log("[-] TLSSocketFactory: " + e); }
        // ── 2. SSLContext.init — FIXED (no recursion) ────────────
        // Store original ref BEFORE overwriting implementation
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var origInit = SSLContext.init; // store original first
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init hooked — injecting AllTrust");
                // Call original ref, NOT this.init() — prevents stack overflow
                origInit.call(this, km, [getAllTrust()], sr);
            };
            console.log("[+] SSLContext.init hooked");
        } catch (e) { console.log("[-] SSLContext: " + e); }
        // ── 3. Conscrypt (most important for HTTPS errors) ────────
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            var ArrayList = Java.use("java.util.ArrayList");
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                console.log("[+] checkTrustedRecursive bypassed");
                return ArrayList.$new();
            };
            // FIXED: verifyChain only takes 1 arg in most Android versions
            try {
                TrustManagerImpl.verifyChain.overload(
                    'java.util.List',
                    'java.util.List',
                    'java.lang.String',
                    'boolean',
                    'byte[]',
                    'byte[]'
                ).implementation = function (chain) {
                    console.log("[+] verifyChain bypassed");
                    return chain;
                };
            } catch(e) {
                TrustManagerImpl.verifyChain.implementation = function (chain) {
                    return chain;
                };
            }
            console.log("[+] Conscrypt hooked");
        } catch (e) { console.log("[-] Conscrypt: " + e); }
        // ── 4. OkHttp3 CertificatePinner ─────────────────────────
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            CertPinner.check.overload("java.lang.String", "java.util.List")
                .implementation = function (host) {
                    console.log("[+] OkHttp3 pin bypass (List): " + host);
                };
            CertPinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;")
                .implementation = function (host) {
                    console.log("[+] OkHttp3 pin bypass (Cert[]): " + host);
                };
            console.log("[+] OkHttp3 CertificatePinner hooked");
        } catch (e) { console.log("[-] OkHttp3: " + e); }
        // ── 5. OkHttpClient Builder — clear pinner at build time ──
        try {
            var Builder = Java.use("okhttp3.OkHttpClient$Builder");
            Builder.build.implementation = function () {
                try {
                    var emptyPinner = Java.use("okhttp3.CertificatePinner$Builder")
                        .$new().build();
                    this.certificatePinner(emptyPinner);
                } catch(e) {}
                return this.build();
            };
            console.log("[+] OkHttpClient builder pinning cleared");
        } catch (e) { console.log("[-] OkHttpClient builder: " + e); }
        // ── 6. WebViewClient SSL errors ───────────────────────────
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (wv, handler, err) {
                console.log("[+] WebViewClient SSL error bypassed");
                handler.proceed();
            };
            console.log("[+] WebViewClient hooked");
        } catch (e) { console.log("[-] WebViewClient: " + e); }
        // ── 7. HttpsURLConnection — FIXED (don't suppress, hook TM) 
        // Do NOT block setSSLSocketFactory — breaks connection
        // Instead hook the HostnameVerifier to always return true
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            var AllVerifier = Java.registerClass({
                implements: [HostnameVerifier],
                methods: {
                    verify: function (hostname, session) {
                        console.log("[+] HostnameVerifier bypassed: " + hostname);
                        return true;
                    }
                }
            });
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hv) {
                console.log("[+] setDefaultHostnameVerifier → AllVerifier injected");
                this.setDefaultHostnameVerifier(AllVerifier.$new());
            };
            console.log("[+] HttpsURLConnection HostnameVerifier hooked");
        } catch (e) { console.log("[-] HttpsURLConnection: " + e); }
        console.log("[+] All SSL hooks applied");
        console.log("[!] Proxy: set device proxy to 10.0.2.2:8082");
    });
}, 1000);
