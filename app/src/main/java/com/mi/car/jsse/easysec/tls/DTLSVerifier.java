package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsCrypto;
import com.mi.car.jsse.easysec.tls.crypto.TlsMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsMACOutputStream;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;

public class DTLSVerifier {
    private final TlsMAC cookieMAC;
    private final TlsMACOutputStream cookieMACOutputStream;

    private static TlsMAC createCookieMAC(TlsCrypto crypto) {
        TlsMAC mac = crypto.createHMAC(3);
        byte[] secret = new byte[mac.getMacLength()];
        crypto.getSecureRandom().nextBytes(secret);
        mac.setKey(secret, 0, secret.length);
        return mac;
    }

    public DTLSVerifier(TlsCrypto crypto) {
        this.cookieMAC = createCookieMAC(crypto);
        this.cookieMACOutputStream = new TlsMACOutputStream(this.cookieMAC);
    }

    public synchronized DTLSRequest verifyRequest(byte[] clientID, byte[] data, int dataOff, int dataLen, DatagramSender sender) {
        boolean resetCookieMAC = true;

        DTLSRequest var9;
        try {
            this.cookieMAC.update(clientID, 0, clientID.length);
            DTLSRequest request = DTLSReliableHandshake.readClientRequest(data, dataOff, dataLen, this.cookieMACOutputStream);
            if (null == request) {
                return null;
            }

            byte[] expectedCookie = this.cookieMAC.calculateMAC();
            resetCookieMAC = false;
            if (!Arrays.constantTimeAreEqual(expectedCookie, request.getClientHello().getCookie())) {
                DTLSReliableHandshake.sendHelloVerifyRequest(sender, request.getRecordSeq(), expectedCookie);
                return null;
            }

            var9 = request;
        } catch (IOException var13) {
            return null;
        } finally {
            if (resetCookieMAC) {
                this.cookieMAC.reset();
            }

        }

        return var9;
    }
}

