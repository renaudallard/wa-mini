// Frida script to extract WhatsApp registration HMAC key
// Target: WhatsApp 2.26.4.71
// Usage:
//   1. Install WhatsApp APK on rooted Android device/emulator
//   2. Start Frida server on device
//   3. Run: frida -U -f com.whatsapp -l frida_extract_key.js --no-pause
//   4. Enter phone number and tap Next to trigger registration
//   5. Key will be printed when HMAC is called

console.log("[*] WhatsApp HMAC Key Extractor v2");
console.log("[*] Waiting for WhatsApp to load...");

// Helper functions
function hexdump(buffer) {
    var bytes = new Uint8Array(buffer);
    var hex = "";
    for (var i = 0; i < bytes.length; i++) {
        hex += ("0" + bytes[i].toString(16)).slice(-2);
    }
    return hex;
}

function arrayToBase64(buffer) {
    var bytes = new Uint8Array(buffer);
    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    var result = "";
    var i = 0;
    while (i < bytes.length) {
        var a = bytes[i++] || 0;
        var b = bytes[i++] || 0;
        var c = bytes[i++] || 0;
        var n = (a << 16) | (b << 8) | c;
        result += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] +
                  chars[(n >> 6) & 63] + chars[n & 63];
    }
    var pad = bytes.length % 3;
    if (pad === 1) result = result.slice(0, -2) + "==";
    else if (pad === 2) result = result.slice(0, -1) + "=";
    return result;
}

function javaArrayToUint8Array(javaArray) {
    var len = javaArray.length;
    var arr = new Uint8Array(len);
    for (var i = 0; i < len; i++) {
        arr[i] = javaArray[i] & 0xff;
    }
    return arr;
}

// Wait for Java to be ready
Java.perform(function() {
    console.log("[*] Java VM attached");

    // Hook Java SecretKeySpec - this is where HMAC keys are set
    try {
        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");

        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function(keyBytes, algorithm) {
            console.log("\n[SecretKeySpec] Algorithm: " + algorithm + ", Key length: " + keyBytes.length);

            // We're looking for 80-byte keys used with HMAC-SHA1
            if (keyBytes.length === 80 && algorithm.toLowerCase().includes("hmac")) {
                console.log("\n[***] FOUND 80-byte HMAC KEY! [***]");
                var arr = javaArrayToUint8Array(keyBytes);
                console.log("[*] KEY (hex): " + hexdump(arr.buffer));
                console.log("[*] KEY (base64): " + arrayToBase64(arr.buffer));
                console.log("[***] Copy the base64 value above to WA_KEY in register.c [***]\n");
            }

            // Also log other interesting keys
            if (algorithm.toLowerCase().includes("hmac") && keyBytes.length > 16) {
                console.log("  Key bytes: " + keyBytes.length);
                var arr = javaArrayToUint8Array(keyBytes);
                console.log("  Key (hex): " + hexdump(arr.buffer).substring(0, 64) + "...");
            }

            return this.$init(keyBytes, algorithm);
        };
        console.log("[+] Hooked javax.crypto.spec.SecretKeySpec");
    } catch(e) {
        console.log("[-] Could not hook SecretKeySpec: " + e);
    }

    // Hook Mac.init for additional coverage
    try {
        var Mac = Java.use("javax.crypto.Mac");

        Mac.init.overload("java.security.Key").implementation = function(key) {
            var encoded = key.getEncoded();
            var algorithm = key.getAlgorithm();
            console.log("\n[Mac.init] Algorithm: " + algorithm + ", Key length: " + encoded.length);

            if (encoded.length === 80) {
                console.log("\n[***] FOUND 80-byte KEY in Mac.init! [***]");
                var arr = javaArrayToUint8Array(encoded);
                console.log("[*] KEY (hex): " + hexdump(arr.buffer));
                console.log("[*] KEY (base64): " + arrayToBase64(arr.buffer));
                console.log("[***] Copy the base64 value above to WA_KEY in register.c [***]\n");
            }

            return this.init(key);
        };
        console.log("[+] Hooked javax.crypto.Mac.init");
    } catch(e) {
        console.log("[-] Could not hook Mac.init: " + e);
    }

    // Hook Base64.decode to catch when the key is decoded
    try {
        var Base64 = Java.use("android.util.Base64");

        Base64.decode.overload("java.lang.String", "int").implementation = function(str, flags) {
            var result = this.decode(str, flags);

            // 80 bytes base64 encoded is ~108 characters
            if (result.length === 80) {
                console.log("\n[Base64.decode] Decoded 80 bytes from: " + str);
                var arr = javaArrayToUint8Array(result);
                console.log("[*] Decoded (hex): " + hexdump(arr.buffer));
                console.log("[*] Decoded (base64): " + arrayToBase64(arr.buffer));
            }

            return result;
        };
        console.log("[+] Hooked android.util.Base64.decode");
    } catch(e) {
        console.log("[-] Could not hook Base64.decode: " + e);
    }

    // Hook the obfuscated string decoder in X/0fT class
    try {
        var cls0fT = Java.use("X.0fT");

        // Hook the A00 XOR decoder method
        cls0fT.A00.implementation = function(encoded) {
            var decoded = this.A00(encoded);

            // Log interesting decoded strings (potential keys)
            if (decoded.length > 50 && decoded.length < 150) {
                console.log("\n[0fT.A00] Decoded: " + decoded + " (" + decoded.length + " chars)");
            }

            return decoded;
        };
        console.log("[+] Hooked X/0fT.A00 (string decoder)");
    } catch(e) {
        console.log("[-] Could not hook X/0fT.A00: " + e);
    }

    // Hook the HMAC function in X/00O class
    try {
        var cls00O = Java.use("X.00O");

        cls00O.A0L.overload("[B", "[[B").implementation = function(key, data) {
            console.log("\n[00O.A0L] HMAC called with key length: " + key.length);

            if (key.length === 80) {
                console.log("\n[***] FOUND 80-byte HMAC KEY in 00O.A0L! [***]");
                var arr = javaArrayToUint8Array(key);
                console.log("[*] KEY (hex): " + hexdump(arr.buffer));
                console.log("[*] KEY (base64): " + arrayToBase64(arr.buffer));
                console.log("[***] Copy the base64 value above to WA_KEY in register.c [***]\n");
            }

            return this.A0L(key, data);
        };
        console.log("[+] Hooked X/00O.A0L (HMAC function)");
    } catch(e) {
        console.log("[-] Could not hook X/00O.A0L: " + e);
    }

    // Hook native HMAC functions (BoringSSL/mbedtls)
    var modules = Process.enumerateModules();
    modules.forEach(function(mod) {
        if (mod.name.includes("ssl") || mod.name.includes("crypto") ||
            mod.name.includes("whatsapp") || mod.name.includes("merged")) {
            console.log("[*] Checking module: " + mod.name);

            // Look for HMAC functions
            try {
                var hmac_init = Module.findExportByName(mod.name, "HMAC_Init_ex");
                if (hmac_init) {
                    Interceptor.attach(hmac_init, {
                        onEnter: function(args) {
                            var keylen = args[2].toInt32();
                            console.log("[HMAC_Init_ex] keylen=" + keylen);
                            if (keylen === 80) {
                                console.log("\n[***] FOUND 80-byte native HMAC KEY! [***]");
                                var key = args[1].readByteArray(80);
                                console.log("[*] KEY (hex): " + hexdump(key));
                                console.log("[*] KEY (base64): " + arrayToBase64(key));
                            }
                        }
                    });
                    console.log("[+] Hooked HMAC_Init_ex in " + mod.name);
                }
            } catch(e) {}

            try {
                var hmac = Module.findExportByName(mod.name, "HMAC");
                if (hmac) {
                    Interceptor.attach(hmac, {
                        onEnter: function(args) {
                            var keylen = args[2].toInt32();
                            console.log("[HMAC] keylen=" + keylen);
                            if (keylen === 80) {
                                console.log("\n[***] FOUND 80-byte native HMAC KEY! [***]");
                                var key = args[1].readByteArray(80);
                                console.log("[*] KEY (hex): " + hexdump(key));
                                console.log("[*] KEY (base64): " + arrayToBase64(key));
                            }
                        }
                    });
                    console.log("[+] Hooked HMAC in " + mod.name);
                }
            } catch(e) {}
        }
    });

    console.log("\n[*] All hooks installed!");
    console.log("[*] Now enter a phone number in WhatsApp and tap 'Next' to trigger registration.");
    console.log("[*] The 80-byte HMAC key will be captured and displayed.\n");
});
