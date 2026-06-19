Java.perform(function () {
    console.log("[+] Palma Full Bypass Script Started");
    Java.use("android.os.Build").PRODUCT.value = "gracerltexx";
    Java.use("android.os.Build").MANUFACTURER.value = "samsung";
    Java.use("android.os.Build").BRAND.value = "samsung";
    Java.use("android.os.Build").DEVICE.value = "gracerlte";
    Java.use("android.os.Build").MODEL.value = "SM-N935F";
    Java.use("android.os.Build").HARDWARE.value = "samsungexynos8890";
    Java.use("android.os.Build").FINGERPRINT.value = "samsung/gracerltexx/gracerlte:8.0.0/R16NW/N935FXXS4BRK2:user/release-keys";
    console.log("[+] Emulator bypass done");
});
setTimeout(function () {
    Java.perform(function () {
        console.log("[+] Applying Aggressive SSL Unpinning...");
        try {
            const TLSSocketFactory = Java.use("com.manappuram.palma.utils.TLSSocketFactory");
            TLSSocketFactory.$init.implementation = function () {
                console.log("[+] Hooked TLSSocketFactory - Blind Trust Applied");
                const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                const AllTrust = Java.registerClass({
                    name: "palma.AllTrust",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function(chain, authType) {
                            console.log("[+] Palma checkServerTrusted bypassed");
                        },
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                this.trustManagers.value = [AllTrust.$new()];
                const SSLContext = Java.use("javax.net.ssl.SSLContext");
                const ctx = SSLContext.getInstance("TLSv1.3");
                ctx.init(null, this.trustManagers.value, null);
                this.delegate.value = ctx.getSocketFactory();
            };
        } catch (e) { console.log("[-] TLSSocketFactory not found"); }
        try {
            const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            const ArrayList = Java.use("java.util.ArrayList");
            TrustManagerImpl.checkTrustedRecursive.implementation = function () {
                console.log("[+] Bypassed checkTrustedRecursive");
                return ArrayList.$new();
            };
            TrustManagerImpl.verifyChain.implementation = function (chain, trustAnchor, host) {
                console.log("[+] Bypassed verifyChain for " + host);
                return chain;
            };
        } catch (e) {}
        try {
            const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            const SSLContext = Java.use("javax.net.ssl.SSLContext");
            SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;', 
                '[Ljavax.net.ssl.TrustManager;', 
                'java.security.SecureRandom'
            ).implementation = function (keyManager, trustManager, secureRandom) {
                console.log("[+] SSLContext.init bypassed with all-trust");
                const AllTrust = Java.registerClass({
                    name: "AllTrustGeneric",
                    implements: [X509TrustManager],
                    methods: {
                        checkClientTrusted: function() {},
                        checkServerTrusted: function() {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                return this.init(keyManager, [AllTrust.$new()], secureRandom);
            };
        } catch (e) {}
        try {
            Java.use("okhttp3.CertificatePinner").check.overload('java.lang.String', 'java.util.List').implementation = function (host, chain) {
                console.log("[+] OkHttp pinning bypassed for " + host);
                return;
            };
        } catch (e) {}
        try {
            Java.use("javax.net.ssl.HttpsURLConnection").setSSLSocketFactory.implementation = function (factory) {
                console.log("[+] HttpsURLConnection setSSLSocketFactory bypassed");
                return;
            };
        } catch (e) {}
        console.log("[+] All hooks applied. Force stop app and try login again.");
    });
}, 0);