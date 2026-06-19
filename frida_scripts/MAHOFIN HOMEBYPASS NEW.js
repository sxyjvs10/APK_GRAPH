setImmediate(function () {
    Java.perform(function () {
        console.log("[*] Script loaded");
        try {
            var LoginFragment = Java.use("com.Macom.emicollection.content.login.presentation.LoginFragment");
            LoginFragment.validateSystemEnvironment.implementation = function () {
                console.log("[+] Bypassed validateSystemEnvironment");
                return true;
            };
            LoginFragment.verifyRuntimeIntegrity.implementation = function () {
                console.log("[+] Bypassed verifyRuntimeIntegrity");
                return false;
            };
            LoginFragment.showSecurityDialog.implementation = function (msg) {
                console.log("[+] Blocked security dialog: " + msg);
            };
            var Activity = Java.use("android.app.Activity");
            Activity.finish.implementation = function () {
                console.log("[+] Prevented app exit");
            };
            console.log("[+] App-specific bypass done");
        } catch (e) {
            console.log("[-] App-specific hook failed: " + e);
        }
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                if (path.includes("su") || path.includes("magisk")) {
                    console.log("[+] Blocked root file check: " + path);
                    return false;
                }
                return this.exists();
            };
            var Runtime = Java.use("java.lang.Runtime");
            Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmd) {
                var command = cmd.toString();
                if (command.includes("su") || command.includes("getprop")) {
                    console.log("[+] Blocked command: " + command);
                    throw new Error("Command blocked");
                }
                return this.exec(cmd);
            };
            console.log("[+] Root bypass active");
        } catch (e) {
            console.log("[-] Root bypass failed: " + e);
        }
        try {
            var HostVerifier = Java.use("com.Macom.emicollection.app.common.HostNameVerifierSSL");
            HostVerifier.verify.implementation = function (host, session) {
                console.log("[🔥] Bypassed HostNameVerifierSSL: " + host);
                return true;
            };
            console.log("[+] Custom HostNameVerifierSSL bypassed");
        } catch (e) {
            console.log("[-] HostNameVerifierSSL hook failed: " + e);
        }
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");
            var TrustManager = Java.registerClass({
                name: "com.bypass.TrustManager",
                implements: [X509TrustManager],
                methods: {
                    checkClientTrusted: function () {},
                    checkServerTrusted: function () {},
                    getAcceptedIssuers: function () { return []; }
                }
            });
            SSLContext.init.overload(
                "[Ljavax.net.ssl.KeyManager;",
                "[Ljavax.net.ssl.TrustManager;",
                "java.security.SecureRandom"
            ).implementation = function (km, tm, sr) {
                console.log("[+] SSLContext hijacked");
                this.init(km, [TrustManager.$new()], sr);
            };
            console.log("[+] Generic SSL bypass active");
        } catch (e) {
            console.log("[-] Generic SSL hook failed: " + e);
        }
        try {
            var CertPinner = Java.use("okhttp3.CertificatePinner");
            CertPinner.check.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                console.log("[+] OkHttp bypass: " + a);
                return;
            };
            console.log("[+] OkHttp bypass ready");
        } catch (e) {
            console.log("[-] OkHttp not used");
        }
        try {
            var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TrustManagerImpl.verifyChain.implementation = function (chain, anchors, host) {
                console.log("[+] TrustManagerImpl bypass: " + host);
                return chain;
            };
            console.log("[+] TrustManagerImpl bypass active");
        } catch (e) {
            console.log("[-] TrustManagerImpl not hooked");
        }
        console.log("=======================================");
        console.log("[🚀] ALL BYPASSES LOADED SUCCESSFULLY");
        console.log("=======================================");
    });
});