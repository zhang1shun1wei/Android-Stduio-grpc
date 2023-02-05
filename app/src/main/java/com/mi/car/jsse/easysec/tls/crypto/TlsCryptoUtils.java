package com.mi.car.jsse.easysec.tls.crypto;

import com.mi.car.jsse.easysec.tls.HashAlgorithm;
import com.mi.car.jsse.easysec.tls.MACAlgorithm;
import com.mi.car.jsse.easysec.tls.PRFAlgorithm;
import com.mi.car.jsse.easysec.tls.SignatureAlgorithm;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.io.IOException;

public abstract class TlsCryptoUtils {
    private static final byte[] TLS13_PREFIX = {116, 108, 115, 49, 51, 32};

    public static int getHash(short hashAlgorithm) {
        switch (hashAlgorithm) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
            case 4:
                return 4;
            case 5:
                return 5;
            case 6:
                return 6;
            default:
                throw new IllegalArgumentException("specified HashAlgorithm invalid: " + HashAlgorithm.getText(hashAlgorithm));
        }
    }

    public static int getHashForHMAC(int macAlgorithm) {
        switch (macAlgorithm) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 4;
            case 4:
                return 5;
            case 5:
                return 6;
            default:
                throw new IllegalArgumentException("specified MACAlgorithm not an HMAC: " + MACAlgorithm.getText(macAlgorithm));
        }
    }

    public static int getHashForPRF(int prfAlgorithm) {
        switch (prfAlgorithm) {
            case 0:
            case 1:
                throw new IllegalArgumentException("legacy PRF not a valid algorithm");
            case 2:
            case 4:
                return 4;
            case 3:
            case 5:
                return 5;
            case 6:
            default:
                throw new IllegalArgumentException("unknown PRFAlgorithm: " + PRFAlgorithm.getText(prfAlgorithm));
            case 7:
                return 7;
        }
    }

    public static int getHashInternalSize(int cryptoHashAlgorithm) {
        switch (cryptoHashAlgorithm) {
            case 1:
            case 2:
            case 3:
            case 4:
            case 7:
                return 64;
            case 5:
            case 6:
                return 128;
            default:
                throw new IllegalArgumentException();
        }
    }

    public static int getHashOutputSize(int cryptoHashAlgorithm) {
        switch (cryptoHashAlgorithm) {
            case 1:
                return 16;
            case 2:
                return 20;
            case 3:
                return 28;
            case 4:
            case 7:
                return 32;
            case 5:
                return 48;
            case 6:
                return 64;
            default:
                throw new IllegalArgumentException();
        }
    }

    public static int getSignature(short signatureAlgorithm) {
        switch (signatureAlgorithm) {
            case 1:
                return 1;
            case 2:
                return 2;
            case 3:
                return 3;
            case 4:
                return 4;
            case 5:
                return 5;
            case 6:
                return 6;
            case 7:
                return 7;
            case 8:
                return 8;
            case 9:
                return 9;
            case 10:
                return 10;
            case 11:
                return 11;
            case 64:
                return 64;
            case 65:
                return 65;
            default:
                throw new IllegalArgumentException("specified SignatureAlgorithm invalid: " + SignatureAlgorithm.getText(signatureAlgorithm));
        }
    }

    public static TlsSecret hkdfExpandLabel(TlsSecret secret, int cryptoHashAlgorithm, String label, byte[] context, int length) throws IOException {
        int labelLength = label.length();
        if (labelLength < 1) {
            throw new TlsFatalAlert((short) 80);
        }
        int contextLength = context.length;
        int expandedLabelLength = TLS13_PREFIX.length + labelLength;
        byte[] hkdfLabel = new byte[(expandedLabelLength + 1 + 2 + contextLength + 1)];
        TlsUtils.checkUint16(length);
        TlsUtils.writeUint16(length, hkdfLabel, 0);
        TlsUtils.checkUint8(expandedLabelLength);
        TlsUtils.writeUint8(expandedLabelLength, hkdfLabel, 2);
        System.arraycopy(TLS13_PREFIX, 0, hkdfLabel, 3, TLS13_PREFIX.length);
        int labelPos = TLS13_PREFIX.length + 1 + 2;
        for (int i = 0; i < labelLength; i++) {
            hkdfLabel[labelPos + i] = (byte) label.charAt(i);
        }
        TlsUtils.writeOpaque8(context, hkdfLabel, expandedLabelLength + 1 + 2);
        return secret.hkdfExpand(cryptoHashAlgorithm, hkdfLabel, length);
    }
}
