// final_bypass.js
Java.perform(function () {

    // ── Block app self-termination ─────────────────────
    try {
        Java.use("java.lang.System").exit.implementation = function (c) {
            console.log("[!] System.exit(" + c + ") BLOCKED");
        };
        Java.use("android.os.Process").killProcess.implementation = function (p) {
            console.log("[!] killProcess BLOCKED");
        };
        console.log("[+] Exit hooks installed");
    } catch(e) { console.log("[-] Exit: " + e); }

    // ── RootBeer ───────────────────────────────────────
    try {
        var RootBeer = Java.use("l2.b");
        ["n","o","d","f","g","l","c","e","b"].forEach(function(m) {
            try {
                RootBeer[m].implementation = function () {
                    console.log("[*] RootBeer." + m + " → false");
                    return false;
                };
            } catch(e) {}
        });
        console.log("[+] RootBeer hooked");
    } catch(e) { console.log("[-] RootBeer: " + e); }

    // ── r2.a — Detection Manager ───────────────────────
    try {
        var Manager = Java.use("r2.a");
        Manager.class.getDeclaredMethods().forEach(function (m) {
            var name = m.getName();
            var ret  = m.getReturnType().getName();
            try {
                if (ret === "boolean") {
                    Manager[name].implementation = function () {
                        console.log("[*] r2.a." + name + " → false");
                        return false;
                    };
                }
            } catch(e) {}
        });
        console.log("[+] r2.a Manager hooked");
    } catch(e) { console.log("[-] r2.a: " + e); }

    // ── r2.b — Config class ────────────────────────────
    try {
        var Config = Java.use("r2.b");
        Config.class.getDeclaredMethods().forEach(function (m) {
            var name = m.getName();
            var ret  = m.getReturnType().getName();
            try {
                if (ret === "boolean") {
                    Config[name].implementation = function () {
                        console.log("[*] r2.b." + name + " → false");
                        return false;
                    };
                }
            } catch(e) {}
        });
        console.log("[+] r2.b Config hooked");
    } catch(e) { console.log("[-] r2.b: " + e); }

    // ── r2.c — SafeDevice Flutter Channel ─────────────
    try {
        var SafeDevice = Java.use("r2.c");
        SafeDevice.e.implementation = function (iVar, dVar) {
            try {
                var method = iVar.f2649a.value;
                console.log("[>>>] SafeDevice call: " + method);
                var Bool    = Java.use("java.lang.Boolean");
                var HashMap = Java.use("java.util.HashMap");

                if (method === "isJailBroken")            { dVar.a(Bool.FALSE);     return; }
                if (method === "isRealDevice")             { dVar.a(Bool.TRUE);      return; }
                if (method === "isDevelopmentModeEnable")  { dVar.a(Bool.FALSE);     return; }
                if (method === "usbDebuggingCheck")        { dVar.a(Bool.FALSE);     return; }
                if (method === "isMockLocation")           { dVar.a(Bool.FALSE);     return; }
                if (method === "isOnExternalStorage")      { dVar.a(Bool.FALSE);     return; }
                if (method === "rootDetectionDetails")     { dVar.a(HashMap.$new()); return; }
                if (method === "init")                     { dVar.a(null);           return; }
                if (method === "getPlatformVersion")       { dVar.a("Android 13");   return; }

                this.e(iVar, dVar);
            } catch(e) {
                console.log("[-] Channel call error: " + e);
                try { dVar.a(null); } catch(e2) {}
            }
        };
        console.log("[+] SafeDevice r2.c hooked");
    } catch(e) { console.log("[-] r2.c: " + e); }

    // ── W2 Detection Classes ───────────────────────────
    ["W2.b","W2.d","W2.e","W2.f","W2.g","W2.h"].forEach(function(cls) {
        try {
            var c = Java.use(cls);
            c.class.getDeclaredMethods().forEach(function(m) {
                var name = m.getName();
                var ret  = m.getReturnType().getName();
                try {
                    if (ret === "boolean") {
                        c[name].implementation = function () {
                            console.log("[*] " + cls + "." + name + " → false");
                            return false;
                        };
                    }
                } catch(e) {}
            });
            console.log("[+] " + cls + " hooked");
        } catch(e) { console.log("[-] " + cls + ": " + e); }
    });

    console.log("[====] All bypass hooks installed ====");
});