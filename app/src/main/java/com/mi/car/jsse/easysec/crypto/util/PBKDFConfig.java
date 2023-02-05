package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;

public abstract class PBKDFConfig {
    private final ASN1ObjectIdentifier algorithm;

    protected PBKDFConfig(ASN1ObjectIdentifier algorithm2) {
        this.algorithm = algorithm2;
    }

    public ASN1ObjectIdentifier getAlgorithm() {
        return this.algorithm;
    }
}
