setImmediate(function () {
    Java.perform(function () {
        console.log("[🚀] MAHOFIN v5 loading...");
        try {
            var File = Java.use("java.io.File");
            File.exists.implementation = function () {
                var path = this.getAbsolutePath();
                if (path.includes("su") || path.includes("magisk") ||
                    path.includes("supersu") || path.includes("busybox") ||
                    path.includes("qemu_pipe") || path.includes("qemud")) {
                    console.log("[+] Blocked file: " + path);
                    return false;
                }
                return this.exists();
            };
            var PackageManager = Java.use("android.app.ApplicationPackageManager");
            PackageManager.getPackageInfo.overload("java.lang.String", "int")
            .implementation = function (pkg, flag) {
                if (pkg.includes("magisk") || pkg.includes("supersu") ||
                    pkg.includes("superuser") || pkg.includes("kinguser")) {
                    console.log("[+] Blocked root pkg: " + pkg);
                    pkg = "fake.package.none";
                }
                return this.getPackageInfo(pkg, flag);
            };
            console.log("[✅] Root bypass active");
        } catch (e) { console.log("[-] Root: " + e); }
        try {
            var m31 = Java.use("com.Macom.emicollection.m31");
            var m31Class = m31.class;
            var methods = m31Class.getDeclaredMethods();
            methods.forEach(function(method) {
                var retType = method.getReturnType().getName();
                var methodName = method.getName();
                if (retType === "boolean") {
                    try {
                        m31[methodName].implementation = function () {
                            console.log("[+] m31." + methodName + "() → false");
                            return false;
                        };
                    } catch(e) {}
                }
            });
            console.log("[✅] m31 (RootBeer) bypass active");
        } catch (e) { console.log("[-] m31: " + e); }
        try {
            var FileInputStream = Java.use("java.io.FileInputStream");
            FileInputStream.$init.overload("java.lang.String")
            .implementation = function (path) {
                if (path === "/proc/self/maps" || path === "/proc/self/status") {
                    console.log("[+] Blocked proc read: " + path);
                    return this.$init("/dev/null");
                }
                return this.$init(path);
            };
            console.log("[✅] /proc/self/maps blocked");
        } catch (e) { console.log("[-] FileInputStream: " + e); }
        try {
            var Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function () {
                return false;
            };
            console.log("[✅] Debugger bypass active");
        } catch (e) { console.log("[-] Debug: " + e); }
        Java.scheduleOnMainThread(function () {
            try {
                var ActivityThread = Java.use("android.app.ActivityThread");
                var app = ActivityThread.currentApplication();
                if (app !== null) {
                    var appInfo = app.getApplicationInfo();
                    var FLAG_DEBUGGABLE = 2;
                    appInfo.flags.value = appInfo.flags.value & ~FLAG_DEBUGGABLE;
                    console.log("[✅] FLAG_DEBUGGABLE cleared, flags=" + appInfo.flags.value);
                }
            } catch (e) { console.log("[-] AppInfo flags: " + e); }
        });
        try {
            var Thread = Java.use("java.lang.Thread");
            Thread.getStackTrace.implementation = function () {
                var trace = this.getStackTrace();
                var clean = [];
                for (var i = 0; i < trace.length; i++) {
                    var cls = trace[i].getClassName();
                    if (!cls.includes("de.robv.android.xposed") &&
                        !cls.includes("com.saurik.substrate")) {
                        clean.push(trace[i]);
                    }
                }
                return Java.array("Ljava.lang.StackTraceElement;", clean);
            };
            console.log("[✅] Stack trace sanitized");
        } catch (e) { console.log("[-] StackTrace: " + e); }
        try {
            var Build = Java.use("android.os.Build");
            Build.BRAND.value        = "samsung";
            Build.DEVICE.value       = "SM-G991B";
            Build.MODEL.value        = "SM-G991B";
            Build.MANUFACTURER.value = "samsung";
            Build.FINGERPRINT.value  =
                "samsung/beyond1qltezto/beyond1q:12/SP1A.210812.016/G991BZTS5FVK1:user/release-keys";
            console.log("[✅] Build props spoofed");
        } catch (e) { console.log("[-] Build: " + e); }
        try {
            var Intent = Java.use("android.content.Intent");
            Intent.getIntExtra.overload("java.lang.String", "int")
            .implementation = function (name, def) {
                if (name === "voltage") {
                    return 3850;
                }
                return this.getIntExtra(name, def);
            };
            console.log("[✅] Battery voltage spoofed");
        } catch (e) { console.log("[-] Intent: " + e); }
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    var HostVerifier = Java.use("com.Macom.emicollection.app.common.HostNameVerifierSSL");
                    HostVerifier.verify.implementation = function (host, session) {
                        console.log("[🔥] SSL pinning bypassed: " + host);
                        return true;
                    };
                    console.log("[✅] HostNameVerifierSSL hooked via classloader");
                } catch (e) {}
            },
            onComplete: function () {}
        });
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
            console.log("[✅] TrustAll bypass active");
        } catch (e) { console.log("[-] TrustAll: " + e); }
        try {
            var LoginFragment = Java.use(
                "com.Macom.emicollection.content.login.presentation.LoginFragment"
            );
            LoginFragment.validateSystemEnvironment.implementation = function () {
                console.log("[🔥] validateSystemEnvironment() → true");
                return true;
            };
            LoginFragment.verifyRuntimeIntegrity.implementation = function () {
                console.log("[🔥] verifyRuntimeIntegrity() → false (no threat)");
                return false;
            };
            LoginFragment.checkHardwareCapabilities.implementation = function () {
                console.log("[🔥] checkHardwareCapabilities() → true");
                return true;
            };
            console.log("[✅] LoginFragment security methods hooked");
        } catch (e) { console.log("[-] LoginFragment hooks: " + e); }
        console.log("===========================================");
        console.log("[🔥] MAHOFIN v5 — ALL BYPASSES ACTIVE");
        console.log("===========================================");
    });
});