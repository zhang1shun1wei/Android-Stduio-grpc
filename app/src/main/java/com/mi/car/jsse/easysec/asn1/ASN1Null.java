package com.mi.car.jsse.easysec.asn1;

import java.io.IOException;

public abstract class ASN1Null extends ASN1Primitive {
    static final ASN1UniversalType TYPE = new ASN1UniversalType(ASN1Null.class, 5) {
        /* class com.mi.car.jsse.easysec.asn1.ASN1Null.AnonymousClass1 */

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.asn1.ASN1UniversalType
        public ASN1Primitive fromImplicitPrimitive(DEROctetString octetString) {
            return ASN1Null.createPrimitive(octetString.getOctets());
        }
    };

    public static ASN1Null getInstance(Object o) {
        if (o instanceof ASN1Null) {
            return (ASN1Null) o;
        }
        if (o == null) {
            return null;
        }
        try {
            return (ASN1Null) TYPE.fromByteArray((byte[]) o);
        } catch (IOException e) {
            throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.getMessage());
        }
    }

    public static ASN1Null getInstance(ASN1TaggedObject taggedObject, boolean explicit) {
        return (ASN1Null) TYPE.getContextInstance(taggedObject, explicit);
    }

    ASN1Null() {
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public int hashCode() {
        return -1;
    }

    /* access modifiers changed from: package-private */
    @Override // com.mi.car.jsse.easysec.asn1.ASN1Primitive
    public boolean asn1Equals(ASN1Primitive o) {
        if (!(o instanceof ASN1Null)) {
            return false;
        }
        return true;
    }

    public String toString() {
        return "NULL";
    }

    static ASN1Null createPrimitive(byte[] contents) {
        if (contents.length == 0) {
            return DERNull.INSTANCE;
        }
        throw new IllegalStateException("malformed NULL encoding encountered");
    }
}
