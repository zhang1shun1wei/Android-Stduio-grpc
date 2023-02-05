package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class SABERPublicKey extends ASN1Object {
    private byte[] b;
    private byte[] seed_A;

    public SABERPublicKey(byte[] seed_A2, byte[] b2) {
        this.seed_A = seed_A2;
        this.b = b2;
    }

    private SABERPublicKey(ASN1Sequence seq) {
        this.seed_A = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        this.b = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
    }

    public byte[] getSeed_A() {
        return this.seed_A;
    }

    public byte[] getB() {
        return this.b;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(this.seed_A));
        v.add(new DEROctetString(this.b));
        return new DERSequence(v);
    }

    public static SABERPublicKey getInstance(Object o) {
        if (o instanceof SABERPublicKey) {
            return (SABERPublicKey) o;
        }
        if (o != null) {
            return new SABERPublicKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
