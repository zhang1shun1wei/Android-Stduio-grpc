package com.mi.car.jsse.easysec.asn1.misc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class IDEACBCPar extends ASN1Object {
    ASN1OctetString iv;

    public static IDEACBCPar getInstance(Object o) {
        if (o instanceof IDEACBCPar) {
            return (IDEACBCPar) o;
        }
        if (o != null) {
            return new IDEACBCPar(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public IDEACBCPar(byte[] iv2) {
        this.iv = new DEROctetString(Arrays.clone(iv2));
    }

    private IDEACBCPar(ASN1Sequence seq) {
        if (seq.size() == 1) {
            this.iv = (ASN1OctetString) seq.getObjectAt(0);
        } else {
            this.iv = null;
        }
    }

    public byte[] getIV() {
        if (this.iv != null) {
            return Arrays.clone(this.iv.getOctets());
        }
        return null;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(1);
        if (this.iv != null) {
            v.add(this.iv);
        }
        return new DERSequence(v);
    }
}
