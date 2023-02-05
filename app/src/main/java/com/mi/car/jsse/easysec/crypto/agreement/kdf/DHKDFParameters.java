package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;

public class DHKDFParameters implements DerivationParameters {
    private ASN1ObjectIdentifier algorithm;
    private byte[] extraInfo;
    private int keySize;
    private byte[] z;

    public DHKDFParameters(ASN1ObjectIdentifier algorithm2, int keySize2, byte[] z2) {
        this(algorithm2, keySize2, z2, null);
    }

    public DHKDFParameters(ASN1ObjectIdentifier algorithm2, int keySize2, byte[] z2, byte[] extraInfo2) {
        this.algorithm = algorithm2;
        this.keySize = keySize2;
        this.z = z2;
        this.extraInfo = extraInfo2;
    }

    public ASN1ObjectIdentifier getAlgorithm() {
        return this.algorithm;
    }

    public int getKeySize() {
        return this.keySize;
    }

    public byte[] getZ() {
        return this.z;
    }

    public byte[] getExtraInfo() {
        return this.extraInfo;
    }
}
