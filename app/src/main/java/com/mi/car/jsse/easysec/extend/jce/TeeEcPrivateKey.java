package com.mi.car.jsse.easysec.extend.jce;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

public class TeeEcPrivateKey implements ECPrivateKey {
    public BigInteger getS() {
        return null;
    }

    public String getAlgorithm() {
        return "EC";
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] getEncoded() {
        return new byte[0];
    }

    public ECParameterSpec getParams() {
        return null;
    }
}
