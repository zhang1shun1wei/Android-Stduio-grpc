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

public class PKCS12PBEParams extends ASN1Object {
    ASN1Integer iterations;
    ASN1OctetString iv;

    public PKCS12PBEParams(byte[] salt, int iterations2) {
        this.iv = new DEROctetString(salt);
        this.iterations = new ASN1Integer((long) iterations2);
    }

    private PKCS12PBEParams(ASN1Sequence seq) {
        this.iv = (ASN1OctetString) seq.getObjectAt(0);
        this.iterations = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static PKCS12PBEParams getInstance(Object obj) {
        if (obj instanceof PKCS12PBEParams) {
            return (PKCS12PBEParams) obj;
        }
        if (obj != null) {
            return new PKCS12PBEParams(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public BigInteger getIterations() {
        return this.iterations.getValue();
    }

    public byte[] getIV() {
        return this.iv.getOctets();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.iv);
        v.add(this.iterations);
        return new DERSequence(v);
    }
}
