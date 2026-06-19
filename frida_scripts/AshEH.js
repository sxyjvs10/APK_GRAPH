setImmediate(function () {
    Java.perform(function () {
        console.log("[+] Script started");
        try {
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function () {
                return false;
            };
            console.log("[+] Debug check bypassed");
        } catch (e) {}
        try {
            var System = Java.use("java.lang.System");
            System.exit.implementation = function (code) {
                console.log("[+] Prevented System.exit");
            };
        } catch (e) {}
        try {
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exit.implementation = function (code) {
                console.log("[+] Prevented Runtime.exit");
            };
        } catch (e) {}
        try {
            var Process = Java.use("android.os.Process");
            Process.killProcess.implementation = function (pid) {
                console.log("[+] Prevented killProcess");
            };
        } catch (e) {}
        try {
            var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
            var SSLContext = Java.use('javax.net.ssl.SSLContext');
            var TrustManager = Java.registerClass({
                name: 'dev.asd.TrustManager',
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var SSLContext_init = SSLContext.init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            );
            SSLContext_init.implementation = function (km, tm, sr) {
                console.log('[+] TrustManager bypass');
                SSLContext_init.call(this, km, [TrustManager.$new()], sr);
            };
        } catch (e) {
            console.log("[-] TrustManager failed");
        }
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            TrustManagerImpl.verifyChain.implementation = function () {
                console.log('[+] TrustManagerImpl bypass');
                return arguments[0];
            };
        } catch (e) {}
        try {
            var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
            var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
            var TrustHostnameVerifier = Java.registerClass({
                name: 'dev.asd.TrustHostnameVerifier',
                implements: [HostnameVerifier],
                methods: {
                    verify: function () {
                        return true;
                    }
                }
            });
            HttpsURLConnection.setDefaultHostnameVerifier(TrustHostnameVerifier.$new());
            console.log("[+] HostnameVerifier bypass");
        } catch (e) {}
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function () {
                console.log('[+] OkHttp bypass');
                return;
            };
        } catch (e) {}
        try {
            var WebViewClient = Java.use('android.webkit.WebViewClient');
            WebViewClient.onReceivedSslError.implementation = function (view, handler, error) {
                console.log('[+] WebView SSL bypass');
                handler.proceed();
            };
        } catch (e) {}
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setSSLSocketFactory.implementation = function () {
                console.log("[+] HttpsURLConnection bypass");
            };
        } catch (e) {}
        try {
            var URL = Java.use("java.net.URL");
            URL.openConnection.overload().implementation = function () {
                var url = this.toString();
                console.log("[+] Request: " + url);
                return this.openConnection();
            };
        } catch (e) {}
        console.log("[+] All hooks applied");
    });
});
