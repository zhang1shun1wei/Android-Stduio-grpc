package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsHash;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* access modifiers changed from: package-private */
public class SSL3Utils {
    private static final byte IPAD_BYTE = 54;
    private static final byte OPAD_BYTE = 92;
    private static final byte[] IPAD = genPad(IPAD_BYTE, 48);
    private static final byte[] OPAD = genPad(OPAD_BYTE, 48);
    private static final byte[] SSL_CLIENT = {67, 76, 78, 84};
    private static final byte[] SSL_SERVER = {83, 82, 86, 82};

    SSL3Utils() {
    }

    static byte[] calculateVerifyData(TlsHandshakeHash handshakeHash, boolean isServer) {
        TlsHash prf = handshakeHash.forkPRFHash();
        byte[] sslSender = isServer ? SSL_SERVER : SSL_CLIENT;
        prf.update(sslSender, 0, sslSender.length);
        return prf.calculateHash();
    }

    static void completeCombinedHash(TlsContext context, TlsHash md5, TlsHash sha1) {
        byte[] master_secret = context.getCrypto().adoptSecret(context.getSecurityParametersHandshake().getMasterSecret()).extract();
        completeHash(master_secret, md5, 48);
        completeHash(master_secret, sha1, 40);
    }

    private static void completeHash(byte[] master_secret, TlsHash hash, int padLength) {
        hash.update(master_secret, 0, master_secret.length);
        hash.update(IPAD, 0, padLength);
        byte[] tmp = hash.calculateHash();
        hash.update(master_secret, 0, master_secret.length);
        hash.update(OPAD, 0, padLength);
        hash.update(tmp, 0, tmp.length);
    }

    private static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    static byte[] readEncryptedPMS(InputStream input) throws IOException {
        return Streams.readAll(input);
    }

    static void writeEncryptedPMS(byte[] encryptedPMS, OutputStream output) throws IOException {
        output.write(encryptedPMS);
    }
}
