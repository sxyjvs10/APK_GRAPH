var _allTrustInstance = null;
function getAllTrust() {
    if (_allTrustInstance) return _allTrustInstance;
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var AllTrust = Java.registerClass({
        name: "com.palma.bypass.AllTrustFinal",  // unique name, registered ONCE
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
    console.log("[+] Palma Final Bypass Started");
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
    try {
        var b3a = Java.use("b3.a");
        b3a.m.overload("android.content.Context").implementation = function (ctx) {
            console.log("[+] b3.a.m(Context) blocked — integrity check bypassed");
            return false;
        };
        try { b3a.m.overload().implementation = function () { return false; }; } catch(e) {}
        console.log("[+] b3.a.m() hooked");
    } catch (e) { console.log("[-] b3.a.m(): " + e); }
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
    try {
        var System = Java.use("java.lang.System");
        System.exit.implementation = function (code) {
            console.log("[!] System.exit(" + code + ") blocked");
        };
        console.log("[+] System.exit() neutralized");
    } catch (e) { console.log("[-] System.exit: " + e); }
    try {
        var Activity = Java.use("android.app.Activity");
        Activity.finishAffinity.implementation = function () {
            console.log("[!] finishAffinity() blocked");
        };
        console.log("[+] finishAffinity() neutralized");
    } catch (e) { console.log("[-] finishAffinity: " + e); }
    try {
        var MotionEvent = Java.use("android.view.MotionEvent");
        MotionEvent.getFlags.implementation = function () { return 0; };
        console.log("[+] MotionEvent.getFlags() bypassed");
    } catch (e) { console.log("[-] MotionEvent: " + e); }
    console.log("[+] All root/integrity hooks applied");
});
setTimeout(function () {
    Java.perform(function () {
        console.log("[+] Applying SSL Unpinning...");
        try {
            var TLSSocketFactory = Java.use("com.manappuram.palma.utils.TLSSocketFactory");
            TLSSocketFactory.$init.implementation = function () {
                console.log("[+] TLSSocketFactory.$init hooked");
                var SSLCtx = Java.use("javax.net.ssl.SSLContext").getInstance("TLSv1.2");
                SSLCtx.init(null, [getAllTrust()], null);
                this.$init();
            };
            console.log("[+] TLSSocketFactory hooked");
        } catch (e) { console.log("[-] TLSSocketFactory: " + e); }
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var origInit = SSLContext.init; // store original first
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init hooked — injecting AllTrust");
                origInit.call(this, km, [getAllTrust()], sr);
            };
            console.log("[+] SSLContext.init hooked");
        } catch (e) { console.log("[-] SSLContext: " + e); }
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            var ArrayList = Java.use("java.util.ArrayList");
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                console.log("[+] checkTrustedRecursive bypassed");
                return ArrayList.$new();
            };
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
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (wv, handler, err) {
                console.log("[+] WebViewClient SSL error bypassed");
                handler.proceed();
            };
            console.log("[+] WebViewClient hooked");
        } catch (e) { console.log("[-] WebViewClient: " + e); }
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            var AllVerifier = Java.registerClass({
                name: "com.palma.bypass.AllVerifier",
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
