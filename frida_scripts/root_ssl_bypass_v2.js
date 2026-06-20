setImmediate(function () {
    Java.perform(function () {

        console.log("[🚀] Stable script (no socket break)");

        // ============================================================
        // ✅ 1. ROOT BYPASS
        // ============================================================
        try {
            var File = Java.use("java.io.File");

            File.exists.implementation = function () {
                var path = this.getAbsolutePath();

                if (path.includes("su") || path.includes("magisk")) {
                    console.log("[+] Root file blocked: " + path);
                    return false;
                }

                return this.exists();
            };

            var PackageManager = Java.use("android.app.ApplicationPackageManager");

            PackageManager.getPackageInfo.overload("java.lang.String", "int")
            .implementation = function (pkg, flag) {

                if (pkg.includes("magisk") || pkg.includes("supersu")) {
                    console.log("[+] Blocked root package: " + pkg);
                    pkg = "fake.package";
                }

                return this.getPackageInfo(pkg, flag);
            };

        } catch (e) {}

        // ============================================================
        // 🔥 2. CUSTOM SSL PINNING BYPASS (MAIN)
        // ============================================================
        try {

            HostVerifier.verify.implementation = function (host, session) {
                console.log("[🔥] SSL bypass: " + host);
                return true;
            };

        } catch (e) {}

        // ============================================================
        // 🔥 3. TRUST ALL CERTS (FALLBACK)
        // ============================================================
        try {
            var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
            var SSLContext = Java.use("javax.net.ssl.SSLContext");

            var TrustManager = Java.registerClass({
                name: "dev.bypass.TrustManager",
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

        } catch (e) {}

        console.log("=================================");
        console.log("[🔥] SAFE MODE ACTIVE");
        console.log("=================================");

    });
});