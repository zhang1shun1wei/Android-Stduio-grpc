package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.TlsECConfig;
import com.mi.car.jsse.easysec.util.Arrays;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class TlsECCUtils {
    public static TlsECConfig createNamedECConfig(TlsContext context, int namedGroup) throws IOException {
        if (NamedGroup.getCurveBits(namedGroup) >= 1) {
            return new TlsECConfig(namedGroup);
        }
        throw new TlsFatalAlert((short) 80);
    }

    public static int getMinimumCurveBits(int cipherSuite) {
        return isECCCipherSuite(cipherSuite) ? 1 : 0;
    }

    public static boolean isECCCipherSuite(int cipherSuite) {
        switch (TlsUtils.getKeyExchangeAlgorithm(cipherSuite)) {
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 24:
                return true;
            case 21:
            case 22:
            case 23:
            default:
                return false;
        }
    }

    public static void checkPointEncoding(int namedGroup, byte[] encoding) throws IOException {
        if (TlsUtils.isNullOrEmpty(encoding)) {
            throw new TlsFatalAlert((short) 47);
        }
        switch (namedGroup) {
            case NamedGroup.x25519:
            case NamedGroup.x448:
                return;
            default:
                switch (encoding[0]) {
                    case 4:
                        return;
                    default:
                        throw new TlsFatalAlert((short) 47);
                }
        }
    }

    public static TlsECConfig receiveECDHConfig(TlsContext context, InputStream input) throws IOException {
        int[] clientSupportedGroups;
        if (TlsUtils.readUint8(input) != 3) {
            throw new TlsFatalAlert((short) 40);
        }
        int namedGroup = TlsUtils.readUint16(input);
        if (NamedGroup.refersToAnECDHCurve(namedGroup) && ((clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups()) == null || Arrays.contains(clientSupportedGroups, namedGroup))) {
            return new TlsECConfig(namedGroup);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static void writeECConfig(TlsECConfig ecConfig, OutputStream output) throws IOException {
        writeNamedECParameters(ecConfig.getNamedGroup(), output);
    }

    public static void writeNamedECParameters(int namedGroup, OutputStream output) throws IOException {
        if (!NamedGroup.refersToASpecificCurve(namedGroup)) {
            throw new TlsFatalAlert((short) 80);
        }
        TlsUtils.writeUint8((short) 3, output);
        TlsUtils.checkUint16(namedGroup);
        TlsUtils.writeUint16(namedGroup, output);
    }
}
