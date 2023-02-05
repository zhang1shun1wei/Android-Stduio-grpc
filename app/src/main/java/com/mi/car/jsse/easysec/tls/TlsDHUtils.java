package com.mi.car.jsse.easysec.tls;

import com.mi.car.jsse.easysec.tls.crypto.DHGroup;
import com.mi.car.jsse.easysec.tls.crypto.DHStandardGroups;
import com.mi.car.jsse.easysec.tls.crypto.TlsDHConfig;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.BigIntegers;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;

public class TlsDHUtils {
    public static TlsDHConfig createNamedDHConfig(TlsContext context, int namedGroup) {
        if (namedGroup < 0 || NamedGroup.getFiniteFieldBits(namedGroup) < 1) {
            return null;
        }
        return new TlsDHConfig(namedGroup, TlsUtils.isTLSv13(context));
    }

    public static DHGroup getDHGroup(TlsDHConfig dhConfig) {
        int namedGroup = dhConfig.getNamedGroup();
        if (namedGroup >= 0) {
            return getNamedDHGroup(namedGroup);
        }
        return dhConfig.getExplicitGroup();
    }

    public static DHGroup getNamedDHGroup(int namedGroup) {
        switch (namedGroup) {
            case NamedGroup.ffdhe2048:
                return DHStandardGroups.rfc7919_ffdhe2048;
            case NamedGroup.ffdhe3072:
                return DHStandardGroups.rfc7919_ffdhe3072;
            case NamedGroup.ffdhe4096:
                return DHStandardGroups.rfc7919_ffdhe4096;
            case NamedGroup.ffdhe6144:
                return DHStandardGroups.rfc7919_ffdhe6144;
            case NamedGroup.ffdhe8192:
                return DHStandardGroups.rfc7919_ffdhe8192;
            default:
                return null;
        }
    }

    public static int getMinimumFiniteFieldBits(int cipherSuite) {
        return isDHCipherSuite(cipherSuite) ? 1 : 0;
    }

    public static boolean isDHCipherSuite(int cipherSuite) {
        switch (TlsUtils.getKeyExchangeAlgorithm(cipherSuite)) {
            case 3:
            case 5:
            case 7:
            case 9:
            case 11:
            case 14:
                return true;
            case 4:
            case 6:
            case 8:
            case 10:
            case 12:
            case 13:
            default:
                return false;
        }
    }

    public static int getNamedGroupForDHParameters(BigInteger p, BigInteger g) {
        int[] namedGroups = {NamedGroup.ffdhe2048, NamedGroup.ffdhe3072, NamedGroup.ffdhe4096, NamedGroup.ffdhe6144, NamedGroup.ffdhe8192};
        for (int namedGroup : namedGroups) {
            DHGroup dhGroup = getNamedDHGroup(namedGroup);
            if (dhGroup != null && dhGroup.getP().equals(p) && dhGroup.getG().equals(g)) {
                return namedGroup;
            }
        }
        return -1;
    }

    public static DHGroup getStandardGroupForDHParameters(BigInteger p, BigInteger g) {
        DHGroup[] standardGroups = {DHStandardGroups.rfc7919_ffdhe2048, DHStandardGroups.rfc7919_ffdhe3072, DHStandardGroups.rfc7919_ffdhe4096, DHStandardGroups.rfc7919_ffdhe6144, DHStandardGroups.rfc7919_ffdhe8192, DHStandardGroups.rfc3526_1536, DHStandardGroups.rfc3526_2048, DHStandardGroups.rfc3526_3072, DHStandardGroups.rfc3526_4096, DHStandardGroups.rfc3526_6144, DHStandardGroups.rfc3526_8192, DHStandardGroups.rfc5996_768, DHStandardGroups.rfc5996_1024};
        for (DHGroup dhGroup : standardGroups) {
            if (dhGroup != null && dhGroup.getP().equals(p) && dhGroup.getG().equals(g)) {
                return dhGroup;
            }
        }
        return null;
    }

    public static TlsDHConfig receiveDHConfig(TlsContext context, TlsDHGroupVerifier dhGroupVerifier, InputStream input) throws IOException {
        BigInteger p = readDHParameter(input);
        BigInteger g = readDHParameter(input);
        int namedGroup = getNamedGroupForDHParameters(p, g);
        if (namedGroup < 0) {
            DHGroup dhGroup = getStandardGroupForDHParameters(p, g);
            if (dhGroup == null) {
                dhGroup = new DHGroup(p, null, g, 0);
            }
            if (dhGroupVerifier.accept(dhGroup)) {
                return new TlsDHConfig(dhGroup);
            }
            throw new TlsFatalAlert((short) 71);
        }
        int[] clientSupportedGroups = context.getSecurityParametersHandshake().getClientSupportedGroups();
        if (clientSupportedGroups == null || Arrays.contains(clientSupportedGroups, namedGroup)) {
            return new TlsDHConfig(namedGroup, false);
        }
        throw new TlsFatalAlert((short) 47);
    }

    public static BigInteger readDHParameter(InputStream input) throws IOException {
        return new BigInteger(1, TlsUtils.readOpaque16(input, 1));
    }

    public static void writeDHConfig(TlsDHConfig dhConfig, OutputStream output) throws IOException {
        DHGroup group = getDHGroup(dhConfig);
        writeDHParameter(group.getP(), output);
        writeDHParameter(group.getG(), output);
    }

    public static void writeDHParameter(BigInteger x, OutputStream output) throws IOException {
        TlsUtils.writeOpaque16(BigIntegers.asUnsignedByteArray(x), output);
    }
}
