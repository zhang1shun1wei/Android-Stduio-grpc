package com.mi.car.jsse.easysec.asn1;

public class DERUTF8String extends ASN1UTF8String {
    public static DERUTF8String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUTF8String)) {
            return (DERUTF8String) obj;
        }
        if (obj instanceof ASN1UTF8String) {
            return new DERUTF8String(((ASN1UTF8String) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERUTF8String) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERUTF8String getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERUTF8String)) {
            return getInstance((Object) o);
        }
        return new DERUTF8String(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERUTF8String(String string) {
        super(string);
    }

    DERUTF8String(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
