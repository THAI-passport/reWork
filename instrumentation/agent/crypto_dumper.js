/**
 * crypto_dumper.js: Production-grade cryptographic telemetry tracer for dbug.
 * Intercepts javax.crypto.Cipher to dump:
 *   1. Keys, algorithms, and IVs across IvParameterSpec and GCMParameterSpec
 *   2. Incremental streaming updates (Cipher.update)
 *   3. All Cipher.doFinal overloads including ByteBuffer and zero-argument calls
 */

Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
    const cipherContexts = {};

    function bytesToHex(byteArray) {
        if (!byteArray) return null;
        let hex = [];
        for (let i = 0; i < byteArray.length; i++) {
            let byte = byteArray[i] & 0xFF;
            hex.push((byte < 16 ? "0" : "") + byte.toString(16));
        }
        return hex.join("");
    }

    function bytesToUtf8(byteArray) {
        if (!byteArray) return null;
        try {
            const StringCls = Java.use("java.lang.String");
            return StringCls.$new(byteArray, "UTF-8").toString();
        } catch (e) {
            return null;
        }
    }

    function byteBufferToBytes(bb) {
        if (!bb) return null;
        try {
            const dup = bb.duplicate();
            const rem = dup.remaining();
            if (rem <= 0) return null;
            const arr = Java.array('byte', new Array(rem).fill(0));
            dup.get(arr);
            return arr;
        } catch (e) {
            return null;
        }
    }

    function getOpmodeName(opmode) {
        switch (opmode) {
            case 1: return "ENCRYPT_MODE";
            case 2: return "DECRYPT_MODE";
            case 3: return "WRAP_MODE";
            case 4: return "UNWRAP_MODE";
            default: return `OPMODE_${opmode}`;
        }
    }

    function recordCipherInit(instance, opmode, key, params) {
        let keyHex = null;
        let keyAlgo = null;
        let ivHex = null;

        if (key) {
            try {
                keyAlgo = key.getAlgorithm();
                keyHex = bytesToHex(key.getEncoded());
            } catch (e) {}
        }

        if (params) {
            try {
                const clsName = params.$className;
                if (clsName === "javax.crypto.spec.IvParameterSpec") {
                    const ivSpec = Java.cast(params, IvParameterSpec);
                    ivHex = bytesToHex(ivSpec.getIV());
                } else if (clsName === "javax.crypto.spec.GCMParameterSpec") {
                    const GcmSpec = Java.use("javax.crypto.spec.GCMParameterSpec");
                    const gcm = Java.cast(params, GcmSpec);
                    ivHex = bytesToHex(gcm.getIV());
                }
            } catch (e) {}
        }

        const algo = instance.getAlgorithm();
        const instanceId = instance.hashCode();
        cipherContexts[instanceId] = {
            algorithm: algo,
            opmode: getOpmodeName(opmode),
            key_algorithm: keyAlgo,
            key_hex: keyHex,
            iv_hex: ivHex,
            stream_chunks: []
        };

        send({
            event: "CRYPTO_INIT",
            algorithm: algo,
            opmode: getOpmodeName(opmode),
            key_algorithm: keyAlgo,
            key_hex: keyHex,
            iv_hex: ivHex
        });
    }

    function recordDoFinal(instance, inputBytes, outputBytes) {
        const instanceId = instance.hashCode();
        const ctx = cipherContexts[instanceId] || {};
        const algo = ctx.algorithm || instance.getAlgorithm();

        let finalInput = inputBytes;
        if ((!finalInput || finalInput.length === 0) && ctx.stream_chunks && ctx.stream_chunks.length > 0) {
            // Concatenate streaming chunks if present
            try {
                let totalLen = 0;
                for (let i = 0; i < ctx.stream_chunks.length; i++) totalLen += ctx.stream_chunks[i].length;
                let merged = Java.array('byte', new Array(totalLen).fill(0));
                let pos = 0;
                const SystemCls = Java.use("java.lang.System");
                for (let i = 0; i < ctx.stream_chunks.length; i++) {
                    SystemCls.arraycopy(ctx.stream_chunks[i], 0, merged, pos, ctx.stream_chunks[i].length);
                    pos += ctx.stream_chunks[i].length;
                }
                finalInput = merged;
            } catch (e) {}
        }

        send({
            event: "CRYPTO_DOFINAL",
            algorithm: algo,
            opmode: ctx.opmode || "UNKNOWN",
            key_algorithm: ctx.key_algorithm || null,
            key_hex: ctx.key_hex || null,
            iv_hex: ctx.iv_hex || null,
            input_length: finalInput ? finalInput.length : 0,
            input_hex: bytesToHex(finalInput),
            input_utf8: bytesToUtf8(finalInput),
            output_length: outputBytes ? outputBytes.length : 0,
            output_hex: bytesToHex(outputBytes),
            output_utf8: bytesToUtf8(outputBytes)
        });

        // Reset stream chunks for reuse
        if (ctx.stream_chunks) ctx.stream_chunks = [];
    }

    // -------------------------------------------------------------------------
    // 1. Hook Cipher.init() Overloads
    // -------------------------------------------------------------------------
    try {
        Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
            recordCipherInit(this, opmode, key, params);
            return this.init(opmode, key, params);
        };
    } catch (e) {}

    try {
        Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
            recordCipherInit(this, opmode, key, null);
            return this.init(opmode, key);
        };
    } catch (e) {}

    try {
        Cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function(opmode, key, params) {
            recordCipherInit(this, opmode, key, null);
            return this.init(opmode, key, params);
        };
    } catch (e) {}

    // -------------------------------------------------------------------------
    // 2. Hook Cipher.update() Overloads for Streaming Ciphers
    // -------------------------------------------------------------------------
    try {
        Cipher.update.overload('[B').implementation = function(input) {
            const res = this.update(input);
            const instanceId = this.hashCode();
            if (cipherContexts[instanceId] && input) {
                cipherContexts[instanceId].stream_chunks.push(input);
            }
            return res;
        };
    } catch (e) {}

    try {
        Cipher.update.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
            const res = this.update(input, offset, len);
            const instanceId = this.hashCode();
            if (cipherContexts[instanceId] && input && len > 0) {
                try {
                    const Arrays = Java.use("java.util.Arrays");
                    cipherContexts[instanceId].stream_chunks.push(Arrays.copyOfRange(input, offset, offset + len));
                } catch (e) {}
            }
            return res;
        };
    } catch (e) {}

    // -------------------------------------------------------------------------
    // 3. Hook All Cipher.doFinal() Overloads
    // -------------------------------------------------------------------------
    // Overload 1: doFinal()
    try {
        Cipher.doFinal.overload().implementation = function() {
            const res = this.doFinal();
            recordDoFinal(this, null, res);
            return res;
        };
    } catch (e) {}

    // Overload 2: doFinal(byte[] input)
    try {
        Cipher.doFinal.overload('[B').implementation = function(input) {
            const res = this.doFinal(input);
            recordDoFinal(this, input, res);
            return res;
        };
    } catch (e) {}

    // Overload 3: doFinal(byte[] input, int offset, int len)
    try {
        Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
            const res = this.doFinal(input, offset, len);
            let sliced = null;
            if (input && len > 0) {
                try {
                    const Arrays = Java.use("java.util.Arrays");
                    sliced = Arrays.copyOfRange(input, offset, offset + len);
                } catch (e) {}
            }
            recordDoFinal(this, sliced, res);
            return res;
        };
    } catch (e) {}

    // Overload 4: doFinal(byte[] input, int offset, int len, byte[] output)
    try {
        Cipher.doFinal.overload('[B', 'int', 'int', '[B').implementation = function(input, offset, len, output) {
            const res = this.doFinal(input, offset, len, output);
            let sliced = null;
            if (input && len > 0) {
                try {
                    const Arrays = Java.use("java.util.Arrays");
                    sliced = Arrays.copyOfRange(input, offset, offset + len);
                } catch (e) {}
            }
            recordDoFinal(this, sliced, output);
            return res;
        };
    } catch (e) {}

    // Overload 5: doFinal(byte[] input, int offset, int len, byte[] output, int outputOffset)
    try {
        Cipher.doFinal.overload('[B', 'int', 'int', '[B', 'int').implementation = function(input, offset, len, output, outputOffset) {
            const res = this.doFinal(input, offset, len, output, outputOffset);
            let sliced = null;
            if (input && len > 0) {
                try {
                    const Arrays = Java.use("java.util.Arrays");
                    sliced = Arrays.copyOfRange(input, offset, offset + len);
                } catch (e) {}
            }
            recordDoFinal(this, sliced, output);
            return res;
        };
    } catch (e) {}

    // Overload 6: doFinal(ByteBuffer input, ByteBuffer output)
    try {
        Cipher.doFinal.overload('java.nio.ByteBuffer', 'java.nio.ByteBuffer').implementation = function(inputBB, outputBB) {
            const inBytes = byteBufferToBytes(inputBB);
            const res = this.doFinal(inputBB, outputBB);
            const outBytes = byteBufferToBytes(outputBB);
            recordDoFinal(this, inBytes, outBytes);
            return res;
        };
    } catch (e) {}
});
