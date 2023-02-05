package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.math.BigInteger;

public class PBEParameter extends ASN1Object {
    ASN1Integer iterations;
    ASN1OctetString salt;

    public PBEParameter(byte[] salt2, int iterations2) {
        if (salt2.length != 8) {
            throw new IllegalArgumentException("salt length must be 8");
        }
        this.salt = new DEROctetString(salt2);
        this.iterations = new ASN1Integer((long) iterations2);
    }

    private PBEParameter(ASN1Sequence seq) {
        this.salt = (ASN1OctetString) seq.getObjectAt(0);
        this.iterations = (ASN1Integer) seq.getObjectAt(1);
    }

    public static PBEParameter getInstance(Object obj) {
        if (obj instanceof PBEParameter) {
            return (PBEParameter) obj;
        }
        if (obj != null) {
            return new PBEParameter(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public BigInteger getIterationCount() {
        return this.iterations.getValue();
    }

    public byte[] getSalt() {
        return this.salt.getOctets();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.salt);
        v.add(this.iterations);
        return new DERSequence(v);
    }
}
