console.log("[+] Native bypass script loaded");
setTimeout(function () {
    var modules = Process.enumerateModules();
    modules.forEach(function (m) {
        var name = m.name.toLowerCase();
        if (name.includes("flutter") || name.includes("ssl")) {
            console.log("[*] Checking module:", m.name);
            try {
                var verify = Module.findExportByName(m.name, "SSL_get_verify_result");
                if (verify) {
                    console.log("[+] Hooking SSL_get_verify_result");
                    Interceptor.replace(verify, new NativeCallback(function () {
                        console.log("[+] SSL verification bypassed");
                        return 0; // X509_V_OK
                    }, 'int', ['pointer']));
                }
            } catch (e) {}
            try {
                var write = Module.findExportByName(m.name, "SSL_write");
                if (write) {
                    console.log("[+] Hooking SSL_write");
                    Interceptor.attach(write, {
                        onEnter: function () {
                            console.log("[+] SSL_write called");
                        }
                    });
                }
            } catch (e) {}
            try {
                var read = Module.findExportByName(m.name, "SSL_read");
                if (read) {
                    console.log("[+] Hooking SSL_read");
                    Interceptor.attach(read, {
                        onEnter: function () {
                            console.log("[+] SSL_read called");
                        }
                    });
                }
            } catch (e) {}
        }
    });
}, 2000);
