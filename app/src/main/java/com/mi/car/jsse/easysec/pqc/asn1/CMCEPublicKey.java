package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class CMCEPublicKey extends ASN1Object {
    private byte[] T;

    public CMCEPublicKey(byte[] t) {
        this.T = t;
    }

    public CMCEPublicKey(ASN1Sequence seq) {
        this.T = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
    }

    public byte[] getT() {
        return Arrays.clone(this.T);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(this.T));
        return new DERSequence(v);
    }

    public static CMCEPublicKey getInstance(Object o) {
        if (o instanceof CMCEPrivateKey) {
            return (CMCEPublicKey) o;
        }
        if (o != null) {
            return new CMCEPublicKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }
}
