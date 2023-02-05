package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.util.BigIntegers;
import com.mi.car.jsse.easysec.util.Integers;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Hashtable;

public class TlsSRPUtils {
    public static final Integer EXT_SRP = Integers.valueOf(12);

    public static void addSRPExtension(Hashtable extensions, byte[] identity) throws IOException {
        extensions.put(EXT_SRP, createSRPExtension(identity));
    }

    public static byte[] getSRPExtension(Hashtable extensions) throws IOException {
        byte[] extensionData = TlsUtils.getExtensionData(extensions, EXT_SRP);
        if (extensionData == null) {
            return null;
        }
        return readSRPExtension(extensionData);
    }

    public static byte[] createSRPExtension(byte[] identity) throws IOException {
        if (identity != null) {
            return TlsUtils.encodeOpaque8(identity);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static byte[] readSRPExtension(byte[] extensionData) throws IOException {
        if (extensionData != null) {
            return TlsUtils.decodeOpaque8(extensionData, 1);
        }
        throw new IllegalArgumentException("'extensionData' cannot be null");
    }

    public static BigInteger readSRPParameter(InputStream input) throws IOException {
        return new BigInteger(1, TlsUtils.readOpaque16(input, 1));
    }

    public static void writeSRPParameter(BigInteger x, OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }

    public static boolean isSRPCipherSuite(int cipherSuite) {
        switch (TlsUtils.getKeyExchangeAlgorithm(cipherSuite)) {
            case 21:
            case 22:
            case 23:
                return true;
            default:
                return false;
        }
    }
}
