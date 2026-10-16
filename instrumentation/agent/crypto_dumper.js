/**
 * crypto_dumper.js: Pre-network cryptographic operation tracer for dbug.
 * Intercepts javax.crypto.Cipher to dump algorithms, secret keys, IVs,
 * plaintext buffers, and ciphertexts before TLS transmission.
 */

Java.perform(() => {
    const Cipher = Java.use("javax.crypto.Cipher");
    const IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");

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

    function getOpmodeName(opmode) {
        switch (opmode) {
            case 1: return "ENCRYPT_MODE";
            case 2: return "DECRYPT_MODE";
            case 3: return "WRAP_MODE";
            case 4: return "UNWRAP_MODE";
            default: return `OPMODE_${opmode}`;
        }
    }

    // -------------------------------------------------------------------------
    // 1. Hook Cipher.init() to capture secret keys and IVs
    // -------------------------------------------------------------------------
    // Overload: init(int opmode, Key key, AlgorithmParameterSpec params)
    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(opmode, key, params) {
        let keyHex = null;
        let keyAlgo = null;
        let ivHex = null;

        if (key) {
            try {
                keyAlgo = key.getAlgorithm();
                keyHex = bytesToHex(key.getEncoded());
            } catch (e) {}
        }

        if (params && params.$className === "javax.crypto.spec.IvParameterSpec") {
            try {
                const ivSpec = Java.cast(params, IvParameterSpec);
                ivHex = bytesToHex(ivSpec.getIV());
            } catch (e) {}
        }

        send({
            event: "CRYPTO_INIT",
            algorithm: this.getAlgorithm(),
            opmode: getOpmodeName(opmode),
            key_algorithm: keyAlgo,
            key_hex: keyHex,
            iv_hex: ivHex
        });

        return this.init(opmode, key, params);
    };

    // Overload: init(int opmode, Key key)
    Cipher.init.overload('int', 'java.security.Key').implementation = function(opmode, key) {
        let keyHex = null;
        let keyAlgo = null;

        if (key) {
            try {
                keyAlgo = key.getAlgorithm();
                keyHex = bytesToHex(key.getEncoded());
            } catch (e) {}
        }

        send({
            event: "CRYPTO_INIT",
            algorithm: this.getAlgorithm(),
            opmode: getOpmodeName(opmode),
            key_algorithm: keyAlgo,
            key_hex: keyHex,
            iv_hex: null
        });

        return this.init(opmode, key);
    };

    // -------------------------------------------------------------------------
    // 2. Hook Cipher.doFinal() to capture plaintext and ciphertext buffers
    // -------------------------------------------------------------------------
    // Overload: doFinal(byte[] input)
    Cipher.doFinal.overload('[B').implementation = function(input) {
        const result = this.doFinal(input);
        const algo = this.getAlgorithm();

        send({
            event: "CRYPTO_DOFINAL",
            algorithm: algo,
            input_length: input ? input.length : 0,
            input_hex: bytesToHex(input),
            input_utf8: bytesToUtf8(input),
            output_length: result ? result.length : 0,
            output_hex: bytesToHex(result),
            output_utf8: bytesToUtf8(result)
        });

        return result;
    };

    // Overload: doFinal(byte[] input, int inputOffset, int inputLen)
    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, offset, len) {
        const result = this.doFinal(input, offset, len);
        let slicedInput = null;
        if (input && len > 0) {
            try {
                const Arrays = Java.use("java.util.Arrays");
                slicedInput = Arrays.copyOfRange(input, offset, offset + len);
            } catch (e) {}
        }

        send({
            event: "CRYPTO_DOFINAL",
            algorithm: this.getAlgorithm(),
            input_length: len,
            input_hex: bytesToHex(slicedInput),
            input_utf8: bytesToUtf8(slicedInput),
            output_length: result ? result.length : 0,
            output_hex: bytesToHex(result),
            output_utf8: bytesToUtf8(result)
        });

        return result;
    };
});
