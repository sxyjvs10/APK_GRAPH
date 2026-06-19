var _allTrustInstance = null;
var _allVerifierInstance = null;
function getAllTrust() {
    if (_allTrustInstance) return _allTrustInstance;
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var AllTrust = Java.registerClass({
        name: "com.vruksha.bypass.AllTrustFinal",
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
function getAllVerifier() {
    if (_allVerifierInstance) return _allVerifierInstance;
    var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
    var AllVerifier = Java.registerClass({
        name: "com.vruksha.bypass.AllVerifierFinal",
        implements: [HostnameVerifier],
        methods: {
            verify: function (hostname, session) {
                console.log("[+] HostnameVerifier bypassed: " + hostname);
                return true;
            }
        }
    });
    _allVerifierInstance = AllVerifier.$new();
    return _allVerifierInstance;
}
Java.perform(function () {
    console.log("[+] Vruksha Final Bypass Started");
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
            console.log("[+] b3.a.m(Context) blocked");
            return false;
        };
        try { b3a.m.overload().implementation = function () { return false; }; } catch(e) {}
        console.log("[+] b3.a.m() hooked");
    } catch (e) { console.log("[-] b3.a.m(): " + e); }
    try {
        var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
        RootBeer.isRooted.implementation                        = function () { return false; };
        RootBeer.isRootedWithBusyBoxCheck.implementation        = function () { return false; };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation     = function () { return false; };
        RootBeer.detectRootManagementApps.implementation        = function () { return false; };
        RootBeer.detectPotentiallyDangerousApps.implementation  = function () { return false; };
        RootBeer.checkForBinary.implementation                  = function (b) { return false; };
        RootBeer.checkForDangerousProps.implementation          = function () { return false; };
        RootBeer.checkSuExists.implementation                   = function () { return false; };
        console.log("[+] RootBeer fully bypassed");
    } catch (e) { console.log("[-] RootBeer: " + e); }
    try {
        var CommonUtils = Java.use(
            "com.google.firebase.crashlytics.internal.common.CommonUtils"
        );
        CommonUtils.isRooted.overload("android.content.Context").implementation = function (ctx) {
            console.log("[+] Crashlytics isRooted() → false");
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
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload(
            "java.lang.String", "int"
        ).implementation = function (pkg, flags) {
            var blocked = [
                "com.topjohnwu.magisk",
                "eu.chainfire.supersu",
                "com.noshufou.android.su",
                "de.robv.android.xposed.installer",
                "com.saurik.substrate"
            ];
            for (var i = 0; i < blocked.length; i++) {
                if (pkg === blocked[i]) {
                    console.log("[+] Hiding package: " + pkg);
                    throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                }
            }
            return this.getPackageInfo(pkg, flags);
        };
        console.log("[+] PackageManager spoofed");
    } catch (e) { console.log("[-] PackageManager: " + e); }
    try {
        var File = Java.use("java.io.File");
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            var suPaths = ["/su", "/sbin/su", "/system/bin/su", "/system/xbin/su",
                           "/system/xbin/busybox", "/data/local/su", "/data/local/bin/su"];
            for (var i = 0; i < suPaths.length; i++) {
                if (path === suPaths[i]) {
                    console.log("[+] Hiding su path: " + path);
                    return false;
                }
            }
            return this.exists();
        };
        console.log("[+] File.exists() su paths hidden");
    } catch (e) { console.log("[-] File.exists: " + e); }
    console.log("[+] All root/integrity hooks applied");
});
setTimeout(function () {
    Java.perform(function () {
        console.log("[+] Applying SSL Unpinning...");
        try {
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init hooked — injecting AllTrust");
                this.init(km, [getAllTrust()], sr);
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
                TrustManagerImpl.checkTrusted.overload(
                    '[Ljava.security.cert.X509Certificate;',
                    'java.lang.String',
                    'java.lang.String',
                    'boolean'
                ).implementation = function (chain, host, authType, clientAuth) {
                    console.log("[+] TrustManagerImpl.checkTrusted bypassed: " + host);
                    return ArrayList.$new();
                };
            } catch(e) {
                try {
                    TrustManagerImpl.checkTrusted.implementation = function () {
                        return ArrayList.$new();
                    };
                } catch(e2) { console.log("[-] checkTrusted fallback: " + e2); }
            }
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
                try {
                    TrustManagerImpl.verifyChain.implementation = function (chain) {
                        return chain;
                    };
                } catch(e2) {}
            }
            console.log("[+] Conscrypt TrustManagerImpl hooked");
        } catch (e) { console.log("[-] Conscrypt: " + e); }
        try {
            var X509TME = Java.use("android.net.http.X509TrustManagerExtensions");
            X509TME.checkServerTrusted.overload(
                '[Ljava.security.cert.X509Certificate;',
                'java.lang.String',
                'java.lang.String'
            ).implementation = function (chain, authType, host) {
                console.log("[+] X509TrustManagerExtensions bypassed: " + host);
                return Java.use("java.util.ArrayList").$new();
            };
            console.log("[+] X509TrustManagerExtensions hooked");
        } catch (e) { console.log("[-] X509TrustManagerExtensions: " + e); }
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
            var TrustManagerFactory = Java.use("javax.net.ssl.TrustManagerFactory");
            TrustManagerFactory.getTrustManagers.implementation = function () {
                console.log("[+] TrustManagerFactory.getTrustManagers() hooked");
                return [getAllTrust()];
            };
            console.log("[+] TrustManagerFactory hooked");
        } catch (e) { console.log("[-] TrustManagerFactory: " + e); }
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hv) {
                console.log("[+] setDefaultHostnameVerifier → AllVerifier injected");
                this.setDefaultHostnameVerifier(getAllVerifier());
            };
            HttpsURLConnection.setHostnameVerifier.implementation = function (hv) {
                this.setHostnameVerifier(getAllVerifier());
            };
            console.log("[+] HttpsURLConnection HostnameVerifier hooked");
        } catch (e) { console.log("[-] HttpsURLConnection: " + e); }
        try {
            var WebViewClient = Java.use("android.webkit.WebViewClient");
            WebViewClient.onReceivedSslError.implementation = function (wv, handler, err) {
                console.log("[+] WebViewClient SSL error bypassed");
                handler.proceed();
            };
            console.log("[+] WebViewClient hooked");
        } catch (e) { console.log("[-] WebViewClient: " + e); }
        try {
            var NetworkSecurityTrustManager = Java.use(
                "android.security.net.config.NetworkSecurityTrustManager"
            );
            NetworkSecurityTrustManager.checkPins.implementation = function (chain) {
                console.log("[+] NetworkSecurityTrustManager.checkPins() bypassed");
            };
            console.log("[+] NetworkSecurityTrustManager hooked");
        } catch (e) { console.log("[-] NetworkSecurityTrustManager: " + e); }
        try {
            var RootTrustManager = Java.use(
                "android.security.net.config.RootTrustManager"
            );
            RootTrustManager.checkServerTrusted.overload(
                '[Ljava.security.cert.X509Certificate;',
                'java.lang.String'
            ).implementation = function (chain, authType) {
                console.log("[+] RootTrustManager.checkServerTrusted bypassed");
            };
            console.log("[+] RootTrustManager hooked");
        } catch (e) { console.log("[-] RootTrustManager: " + e); }
        console.log("[+] All SSL hooks applied");
        console.log("[!] Ensure device proxy → 10.0.2.2:8082");
    });
}, 1000);