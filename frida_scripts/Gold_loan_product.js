console.log("[+] Dumper loaded");
function toStr(b) {
    try {
        return Java.use("java.lang.String").$new(b);
    } catch (e) {
        return b;
    }
}
function safe(fn) {
    try { Java.perform(fn); } catch (e) {}
}
safe(function () {
    var Debug = Java.use("android.os.Debug");
    Debug.isDebuggerConnected.implementation = function () {
        return false;
    };
    var File = Java.use("java.io.File");
    File.exists.implementation = function () {
        var p = this.getAbsolutePath();
        if (p.includes("su") || p.includes("magisk")) return false;
        return this.exists();
    };
    console.log("[+] Java bypass active");
});
safe(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.init.overload('int', 'java.security.Key').implementation =
        function (mode, key) {
            console.log("\n[+] Cipher INIT → " + (mode === 1 ? "ENCRYPT" : "DECRYPT"));
            return this.init(mode, key);
        };
});
safe(function () {
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function (data) {
        console.log("\n==============================");
        console.log("[PLAINTEXT]");
        console.log(toStr(data));
        var res = this.doFinal(data);
        console.log("[RESULT]");
        console.log(toStr(res));
        console.log("==============================\n");
        return res;
    };
});
safe(function () {
    var Key = Java.use("javax.crypto.spec.SecretKeySpec");
    Key.$init.overload('[B', 'java.lang.String').implementation =
        function (k, algo) {
            console.log("\n[+] KEY (" + algo + ")");
            console.log(toStr(k));
            return this.$init(k, algo);
        };
});
safe(function () {
    var IV = Java.use("javax.crypto.spec.IvParameterSpec");
    IV.$init.overload('[B').implementation = function (iv) {
        console.log("\n[+] IV");
        console.log(toStr(iv));
        return this.$init(iv);
    };
});
console.log("[+] READY → trigger API");
