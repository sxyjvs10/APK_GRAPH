setTimeout(function () {
    Java.perform(function () {
        console.log("\n=================================================");
        console.log("=================================================\n");
        // ===== 1. NetworkSecurityConfig - already working, keep =====
        try {
            var PinningTrustManager = Java.use(
                "android.security.net.config.NetworkSecurityTrustManager"
            );
            PinningTrustManager.checkPins.implementation = function (chain) {
                console.log("[+] NetworkSecurityTrustManager.checkPins() bypassed");
                return;
            };
            console.log("[+] NetworkSecurityConfig pin check hooked");
        } catch (e) {
            console.log("[-] NetworkSecurityTrustManager: " + e);
        }
        // ===== 2. NetworkSecurityConfig getPins - already working =====
        try {
            var NetworkSecurityConfig = Java.use(
                "android.security.net.config.NetworkSecurityConfig"
            );
            NetworkSecurityConfig.getPins.implementation = function () {
                console.log("[+] NetworkSecurityConfig.getPins() bypassed");
                return Java.use("java.util.HashSet").$new();
            };
            console.log("[+] NetworkSecurityConfig.getPins hooked");
        } catch (e) {
            console.log("[-] NetworkSecurityConfig: " + e);
        }
        // ===== 3. OkHttp3 CertificatePinner - FIXED overload =====
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            // Hook all available overloads
            var checkOverloads = CertPinner.check.overloads;
            checkOverloads.forEach(function (overload) {
                overload.implementation = function () {
                    console.log("[+] okhttp3.CertificatePinner.check() bypassed - overload: " 
                        + overload.argumentTypes.map(function(t){ return t.className; }));
                    return;
                };
            });
            console.log("[+] okhttp3.CertificatePinner ALL overloads hooked");
        } catch (e) {
            console.log("[-] okhttp3.CertificatePinner: " + e);
        }
        // ===== 4. Squareup CertificatePinner - FIXED overload =====
        try {
            var SqPinner = Java.use("com.squareup.okhttp.CertificatePinner");
            var sqOverloads = SqPinner.check.overloads;
            sqOverloads.forEach(function (overload) {
                overload.implementation = function () {
                    console.log("[+] squareup.CertificatePinner.check() bypassed");
                    return;
                };
            });
            console.log("[+] squareup.CertificatePinner ALL overloads hooked");
        } catch (e) {
            console.log("[-] squareup.CertificatePinner: " + e);
        }
        // ===== 5. PROXY DETECTION BYPASS =====
        // App may be detecting proxy via System properties
        try {
            var System = Java.use("java.lang.System");
            System.getProperty.overload("java.lang.String").implementation = function (key) {
                if (key === "http.proxyHost" || key === "https.proxyHost" ||
                    key === "http.proxyPort" || key === "https.proxyPort" ||
                    key === "socksProxyHost") {
                    console.log("[+] Proxy property blocked: " + key);
                    return null;
                }
                return this.getProperty(key);
            };
            console.log("[+] System.getProperty proxy detection hooked");
        } catch (e) {
            console.log("[-] System.getProperty: " + e);
        }
        // ===== 6. ProxySelector bypass =====
        try {
            var ProxySelector = Java.use("java.net.ProxySelector");
            var Proxy = Java.use("java.net.Proxy");
            var ArrayList = Java.use("java.util.ArrayList");
            ProxySelector.getDefault.implementation = function () {
                console.log("[+] ProxySelector.getDefault() bypassed");
                return Java.registerClass({
                    name: "com.vapt.bypass.EmptyProxySelector",
                    superClass: ProxySelector,
                    methods: {
                        select: function (uri) {
                            var list = ArrayList.$new();
                            list.add(Proxy.NO_PROXY.value);
                            return list;
                        },
                        connectFailed: function (uri, addr, ex) {}
                    }
                }).$new();
            };
            console.log("[+] ProxySelector bypass hooked");
        } catch (e) {
            console.log("[-] ProxySelector: " + e);
        }
        // ===== 7. ConnectivityManager - proxy/VPN detection =====
        try {
            var ConnectivityManager = Java.use("android.net.ConnectivityManager");
            ConnectivityManager.getDefaultProxy.implementation = function () {
                console.log("[+] ConnectivityManager.getDefaultProxy() → null");
                return null;
            };
            console.log("[+] ConnectivityManager.getDefaultProxy hooked");
        } catch (e) {
            console.log("[-] ConnectivityManager.getDefaultProxy: " + e);
        }
        // ===== 8. NetworkInfo VPN type detection =====
        try {
            var NetworkInfo = Java.use("android.net.NetworkInfo");
            NetworkInfo.getType.implementation = function () {
                var type = this.getType();
                if (type === 17) { // TYPE_VPN = 17
                    console.log("[+] NetworkInfo.getType() VPN blocked → returning WiFi");
                    return 1; // TYPE_WIFI
                }
                return type;
            };
            console.log("[+] NetworkInfo.getType VPN detection hooked");
        } catch (e) {
            console.log("[-] NetworkInfo.getType: " + e);
        }
        // ===== 9. InetSocketAddress proxy check =====
        try {
            var InetSocketAddress = Java.use("java.net.InetSocketAddress");
            InetSocketAddress.createUnresolved.implementation = function (host, port) {
                console.log("[+] InetSocketAddress.createUnresolved: " + host + ":" + port);
                return this.createUnresolved(host, port);
            };
            console.log("[+] InetSocketAddress.createUnresolved hooked");
        } catch (e) {
            console.log("[-] InetSocketAddress: " + e);
        }
        // ===== 10. Global TrustManager - already working, keep =====
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var BypassTM = Java.registerClass({
                name: "com.vapt.bypass.TrustManagerV3",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function (chain, authType) {},
                    checkServerTrusted: function (chain, authType) {
                        console.log("[+] checkServerTrusted bypassed");
                    },
                    getAcceptedIssuers: function () { return []; }
                }
            });
            var sslCtx = SSLContext.getInstance("TLS");
            sslCtx.init(null, [BypassTM.$new()], null);
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultSSLSocketFactory(sslCtx.getSocketFactory());
            console.log("[+] Global TrustManager bypass installed");
        } catch (e) {
            console.log("[-] Global TrustManager: " + e);
        }
        // ===== 11. HostnameVerifier - already working, keep =====
        try {
            var HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
            var HttpsConn = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsConn.setDefaultHostnameVerifier(
                Java.registerClass({
                    name: "com.vapt.bypass.HostnameVerifierV3",
                    implements: [HostnameVerifier],
                    methods: {
                        verify: function (hostname, session) {
                            console.log("[+] HostnameVerifier bypassed: " + hostname);
                            return true;
                        }
                    }
                }).$new()
            );
            console.log("[+] HostnameVerifier bypass installed");
        } catch (e) {
            console.log("[-] HostnameVerifier: " + e);
        }
        // ===== 12. OkHttpClient Builder strip pinner =====
        try {
            var OkHttpBuilder = Java.use("okhttp3.OkHttpClient$Builder");
            OkHttpBuilder.certificatePinner.overload(
                "okhttp3.CertificatePinner"
            ).implementation = function (pinner) {
                console.log("[+] OkHttpClient.Builder.certificatePinner() stripped");
                var emptyPinner = Java.use("okhttp3.CertificatePinner$Builder")
                    .$new().build();
                return this.certificatePinner(emptyPinner);
            };
            console.log("[+] OkHttpClient.Builder.certificatePinner hooked");
        } catch (e) {
            console.log("[-] OkHttpClient.Builder.certificatePinner: " + e);
        }
        // ===== 13. Conscrypt TrustManagerImpl =====
        try {
            var conscrypt = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            conscrypt.verifyChain.implementation = function (
                untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
            ) {
                console.log("[+] Conscrypt verifyChain bypassed: " + host);
                return untrustedChain;
            };
            console.log("[+] Conscrypt TrustManagerImpl hooked");
        } catch (e) {
            console.log("[-] Conscrypt TrustManagerImpl: " + e);
        }
        // ===== 14. SSLContext.init =====
        try {
            var SSLCtxHook = Java.use("javax.net.ssl.SSLContext");
            SSLCtxHook.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext.init() intercepted");
                var X509TM = Java.use("javax.net.ssl.X509TrustManager");
                var BypassTM2 = Java.registerClass({
                    name: "com.vapt.bypass.TrustManagerSSLCtxV3",
                    implements: [X509TM],
                    methods: {
                        checkClientTrusted: function (chain, authType) {},
                        checkServerTrusted: function (chain, authType) {
                            console.log("[+] SSLContext TM bypassed");
                        },
                        getAcceptedIssuers: function () { return []; }
                    }
                });
                this.init(km, [BypassTM2.$new()], sr);
            };
            console.log("[+] SSLContext.init hooked");
        } catch (e) {
            console.log("[-] SSLContext.init: " + e);
        }
        console.log("\n=================================================");
        console.log("[*] v3 Hooks installed. Try opening the app now.");
        console.log("[*] If still blocked - share network_security_config.xml");
        console.log("=================================================\n");
    });
}, 500);
