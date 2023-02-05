package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;

public class ECGOST3410Parameters extends ECNamedDomainParameters {
    private final ASN1ObjectIdentifier digestParamSet;
    private final ASN1ObjectIdentifier encryptionParamSet;
    private final ASN1ObjectIdentifier publicKeyParamSet;

    public ECGOST3410Parameters(ECDomainParameters ecParameters, ASN1ObjectIdentifier publicKeyParamSet2, ASN1ObjectIdentifier digestParamSet2) {
        this(ecParameters, publicKeyParamSet2, digestParamSet2, null);
    }

    public ECGOST3410Parameters(ECDomainParameters ecParameters, ASN1ObjectIdentifier publicKeyParamSet2, ASN1ObjectIdentifier digestParamSet2, ASN1ObjectIdentifier encryptionParamSet2) {
        super(publicKeyParamSet2, ecParameters);
        if (!(ecParameters instanceof ECNamedDomainParameters) || publicKeyParamSet2.equals((ASN1Primitive) ((ECNamedDomainParameters) ecParameters).getName())) {
            this.publicKeyParamSet = publicKeyParamSet2;
            this.digestParamSet = digestParamSet2;
            this.encryptionParamSet = encryptionParamSet2;
            return;
        }
        throw new IllegalArgumentException("named parameters do not match publicKeyParamSet value");
    }

    public ASN1ObjectIdentifier getPublicKeyParamSet() {
        return this.publicKeyParamSet;
    }

    public ASN1ObjectIdentifier getDigestParamSet() {
        return this.digestParamSet;
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return this.encryptionParamSet;
    }
}
