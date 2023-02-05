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

public class RC2CBCParameter extends ASN1Object {
    ASN1OctetString iv;
    ASN1Integer version;

    public static RC2CBCParameter getInstance(Object o) {
        if (o instanceof RC2CBCParameter) {
            return (RC2CBCParameter) o;
        }
        if (o != null) {
            return new RC2CBCParameter(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public RC2CBCParameter(byte[] iv2) {
        this.version = null;
        this.iv = new DEROctetString(iv2);
    }

    public RC2CBCParameter(int parameterVersion, byte[] iv2) {
        this.version = new ASN1Integer((long) parameterVersion);
        this.iv = new DEROctetString(iv2);
    }

    private RC2CBCParameter(ASN1Sequence seq) {
        if (seq.size() == 1) {
            this.version = null;
            this.iv = (ASN1OctetString) seq.getObjectAt(0);
            return;
        }
        this.version = (ASN1Integer) seq.getObjectAt(0);
        this.iv = (ASN1OctetString) seq.getObjectAt(1);
    }

    public BigInteger getRC2ParameterVersion() {
        if (this.version == null) {
            return null;
        }
        return this.version.getValue();
    }

    public byte[] getIV() {
        return this.iv.getOctets();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        if (this.version != null) {
            v.add(this.version);
        }
        v.add(this.iv);
        return new DERSequence(v);
    }
}
