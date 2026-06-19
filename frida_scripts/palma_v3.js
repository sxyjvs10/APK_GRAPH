Java.perform(function () {
    console.log("[+] Palma Bypass v3 Started");
    try {
        var b3a = Java.use("b3.a");
        b3a.m.overload("android.content.Context").implementation = function (ctx) {
            console.log("[+] b3.a.m(Context) blocked — integrity check bypassed");
            return false;
        };
        try {
            b3a.m.overload().implementation = function () {
                return false;
            };
        } catch(e) {}
        console.log("[+] b3.a.m() hooked");
    } catch (e) { console.log("[-] b3.a.m(): " + e); }
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation = function () {
            console.log("[+] RootBeer.isRooted() → false");
            return false;
        };
        RootBeer.isRootedWithBusyBoxCheck.implementation = function () {
            console.log("[+] RootBeer.isRootedWithBusyBoxCheck() → false");
            return false;
        };
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
    console.log("[+] All v3 hooks applied");
});
setTimeout(function () {
    Java.perform(function () {
        console.log("[+] Applying SSL Unpinning...");
        var sharedTrustManager = null;
        function getAllTrustManager() {
            if (sharedTrustManager) return sharedTrustManager;
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var AllTrust = Java.registerClass({
                name: "com.palma.bypass.AllTrustV3",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {
                        console.log("[+] checkServerTrusted bypassed");
                    },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            sharedTrustManager = AllTrust.$new();
            return sharedTrustManager;
        }
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var origInit = SSLContext.init;
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init hooked");
                origInit.call(this, km, [getAllTrustManager()], sr);
            };
        } catch (e) { console.log("[-] SSLContext: " + e); }
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            var ArrayList = Java.use("java.util.ArrayList");
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                return ArrayList.$new();
            };
            TrustManagerImpl.verifyChain.implementation = function (chain) {
                return chain;
            };
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
        console.log("[+] SSL hooks applied");
        console.log("[+] Run: adb shell am force-stop com.manappuram.palma");
    });
}, 1000);
