package com.mi.car.jsse.easysec.tls.crypto.impl;

import java.io.IOException;

import com.mi.car.jsse.easysec.tls.ExporterLabel;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import com.mi.car.jsse.easysec.util.Arrays;

public class TlsImplUtils {
    public static boolean isSSL(TlsCryptoParameters cryptoParams) {
        return cryptoParams.getServerVersion().isSSL();
    }

    public static boolean isTLSv10(ProtocolVersion version) {
        return ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv10(TlsCryptoParameters cryptoParams) {
        return isTLSv10(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv11(ProtocolVersion version) {
        return ProtocolVersion.TLSv11.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv11(TlsCryptoParameters cryptoParams) {
        return isTLSv11(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv12(ProtocolVersion version) {
        return ProtocolVersion.TLSv12.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv12(TlsCryptoParameters cryptoParams) {
        return isTLSv12(cryptoParams.getServerVersion());
    }

    public static boolean isTLSv13(ProtocolVersion version) {
        return ProtocolVersion.TLSv13.isEqualOrEarlierVersionOf(version.getEquivalentTLSVersion());
    }

    public static boolean isTLSv13(TlsCryptoParameters cryptoParams) {
        return isTLSv13(cryptoParams.getServerVersion());
    }

    public static byte[] calculateKeyBlock(TlsCryptoParameters cryptoParams, int length) {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        return PRF(securityParameters, securityParameters.getMasterSecret(), ExporterLabel.key_expansion, Arrays.concatenate(securityParameters.getServerRandom(), securityParameters.getClientRandom()), length).extract();
    }

    public static TlsSecret PRF(SecurityParameters securityParameters, TlsSecret secret, String asciiLabel, byte[] seed, int length) {
        try {
            return secret.deriveUsingPRF(securityParameters.getPRFAlgorithm(), asciiLabel, seed, length);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static TlsSecret PRF(TlsCryptoParameters cryptoParams, TlsSecret secret, String asciiLabel, byte[] seed, int length) {
        return PRF(cryptoParams.getSecurityParametersHandshake(), secret, asciiLabel, seed, length);
    }
}
