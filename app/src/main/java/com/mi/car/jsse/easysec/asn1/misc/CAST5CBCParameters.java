package com.mi.car.jsse.easysec.asn1.misc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class CAST5CBCParameters extends ASN1Object {
    ASN1OctetString iv;
    ASN1Integer keyLength;

    public static CAST5CBCParameters getInstance(Object o) {
        if (o instanceof CAST5CBCParameters) {
            return (CAST5CBCParameters) o;
        }
        if (o != null) {
            return new CAST5CBCParameters(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public CAST5CBCParameters(byte[] iv2, int keyLength2) {
        this.iv = new DEROctetString(Arrays.clone(iv2));
        this.keyLength = new ASN1Integer((long) keyLength2);
    }

    private CAST5CBCParameters(ASN1Sequence seq) {
        this.iv = (ASN1OctetString) seq.getObjectAt(0);
        this.keyLength = (ASN1Integer) seq.getObjectAt(1);
    }

    public byte[] getIV() {
        return Arrays.clone(this.iv.getOctets());
    }

    public int getKeyLength() {
        return this.keyLength.intValueExact();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.iv);
        v.add(this.keyLength);
        return new DERSequence(v);
    }
}
