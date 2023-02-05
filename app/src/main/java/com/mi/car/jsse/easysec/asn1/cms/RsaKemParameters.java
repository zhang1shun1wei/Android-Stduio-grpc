//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.math.BigInteger;

public class RsaKemParameters extends ASN1Object {
    private final AlgorithmIdentifier keyDerivationFunction;
    private final BigInteger keyLength;

    private RsaKemParameters(ASN1Sequence sequence) {
        if (sequence.size() != 2) {
            throw new IllegalArgumentException("ASN.1 SEQUENCE should be of length 2");
        } else {
            this.keyDerivationFunction = AlgorithmIdentifier.getInstance(sequence.getObjectAt(0));
            this.keyLength = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue();
        }
    }

    public static RsaKemParameters getInstance(Object o) {
        if (o instanceof RsaKemParameters) {
            return (RsaKemParameters)o;
        } else {
            return o != null ? new RsaKemParameters(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public RsaKemParameters(AlgorithmIdentifier keyDerivationFunction, int keyLength) {
        this.keyDerivationFunction = keyDerivationFunction;
        this.keyLength = BigInteger.valueOf((long)keyLength);
    }

    public AlgorithmIdentifier getKeyDerivationFunction() {
        return this.keyDerivationFunction;
    }

    public BigInteger getKeyLength() {
        return this.keyLength;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.keyDerivationFunction);
        v.add(new ASN1Integer(this.keyLength));
        return new DERSequence(v);
    }
}
