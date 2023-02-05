package com.mi.car.jsse.easysec.asn1.est;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.pkcs.Attribute;
import java.io.IOException;

public class AttrOrOID extends ASN1Object implements ASN1Choice {
    private final Attribute attribute;
    private final ASN1ObjectIdentifier oid;

    public AttrOrOID(ASN1ObjectIdentifier oid2) {
        this.oid = oid2;
        this.attribute = null;
    }

    public AttrOrOID(Attribute attribute2) {
        this.oid = null;
        this.attribute = attribute2;
    }

    public static AttrOrOID getInstance(Object obj) {
        if (obj instanceof AttrOrOID) {
            return (AttrOrOID) obj;
        }
        if (obj == null) {
            return null;
        }
        if (obj instanceof ASN1Encodable) {
            ASN1Encodable asn1Prim = ((ASN1Encodable) obj).toASN1Primitive();
            if (asn1Prim instanceof ASN1ObjectIdentifier) {
                return new AttrOrOID(ASN1ObjectIdentifier.getInstance(asn1Prim));
            }
            if (asn1Prim instanceof ASN1Sequence) {
                return new AttrOrOID(Attribute.getInstance(asn1Prim));
            }
        }
        if (obj instanceof byte[]) {
            try {
                return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
            } catch (IOException e) {
                throw new IllegalArgumentException("unknown encoding in getInstance()");
            }
        } else {
            throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
        }
    }

    public boolean isOid() {
        return this.oid != null;
    }

    public ASN1ObjectIdentifier getOid() {
        return this.oid;
    }

    public Attribute getAttribute() {
        return this.attribute;
    }

    public ASN1Primitive toASN1Primitive() {
        if (this.oid != null) {
            return this.oid;
        }
        return this.attribute.toASN1Primitive();
    }
}
