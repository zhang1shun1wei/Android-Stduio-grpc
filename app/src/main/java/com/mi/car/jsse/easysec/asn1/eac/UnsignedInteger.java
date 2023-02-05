package com.mi.car.jsse.easysec.asn1.eac;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import java.math.BigInteger;

public class UnsignedInteger extends ASN1Object {
    private int tagNo;
    private BigInteger value;

    public UnsignedInteger(int tagNo2, BigInteger value2) {
        this.tagNo = tagNo2;
        this.value = value2;
    }

    private UnsignedInteger(ASN1TaggedObject obj) {
        this.tagNo = obj.getTagNo();
        this.value = new BigInteger(1, ASN1OctetString.getInstance(obj, false).getOctets());
    }

    public static UnsignedInteger getInstance(Object obj) {
        if (obj instanceof UnsignedInteger) {
            return (UnsignedInteger) obj;
        }
        if (obj != null) {
            return new UnsignedInteger(ASN1TaggedObject.getInstance(obj));
        }
        return null;
    }

    private byte[] convertValue() {
        byte[] v = this.value.toByteArray();
        if (v[0] != 0) {
            return v;
        }
        byte[] tmp = new byte[(v.length - 1)];
        System.arraycopy(v, 1, tmp, 0, tmp.length);
        return tmp;
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public BigInteger getValue() {
        return this.value;
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERTaggedObject(false, this.tagNo, new DEROctetString(convertValue()));
    }
}
