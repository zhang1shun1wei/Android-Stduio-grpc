package com.mi.car.jsse.easysec.asn1.cryptopro;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import java.util.Enumeration;

public class GOST28147Parameters extends ASN1Object {
    private ASN1OctetString iv;
    private ASN1ObjectIdentifier paramSet;

    public static GOST28147Parameters getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static GOST28147Parameters getInstance(Object obj) {
        if (obj instanceof GOST28147Parameters) {
            return (GOST28147Parameters) obj;
        }
        if (obj != null) {
            return new GOST28147Parameters(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public GOST28147Parameters(byte[] iv2, ASN1ObjectIdentifier paramSet2) {
        this.iv = new DEROctetString(Arrays.clone(iv2));
        this.paramSet = paramSet2;
    }

    private GOST28147Parameters(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.iv = (ASN1OctetString) e.nextElement();
        this.paramSet = (ASN1ObjectIdentifier) e.nextElement();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.iv);
        v.add(this.paramSet);
        return new DERSequence(v);
    }

    public ASN1ObjectIdentifier getEncryptionParamSet() {
        return this.paramSet;
    }

    public byte[] getIV() {
        return Arrays.clone(this.iv.getOctets());
    }
}
