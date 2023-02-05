package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.x9.X9ECParameters;
import com.mi.car.jsse.easysec.math.ec.ECConstants;
import com.mi.car.jsse.easysec.math.ec.ECCurve;
import com.mi.car.jsse.easysec.math.ec.ECPoint;
import java.math.BigInteger;

public class ECNamedDomainParameters extends ECDomainParameters {
    private ASN1ObjectIdentifier name;

    public ECNamedDomainParameters(ASN1ObjectIdentifier name2, ECCurve curve, ECPoint G, BigInteger n) {
        this(name2, curve, G, n, ECConstants.ONE, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name2, ECCurve curve, ECPoint G, BigInteger n, BigInteger h) {
        this(name2, curve, G, n, h, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name2, ECCurve curve, ECPoint G, BigInteger n, BigInteger h, byte[] seed) {
        super(curve, G, n, h, seed);
        this.name = name2;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name2, ECDomainParameters domainParameters) {
        super(domainParameters.getCurve(), domainParameters.getG(), domainParameters.getN(), domainParameters.getH(), domainParameters.getSeed());
        this.name = name2;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier name2, X9ECParameters x9) {
        super(x9);
        this.name = name2;
    }

    public ASN1ObjectIdentifier getName() {
        return this.name;
    }
}
