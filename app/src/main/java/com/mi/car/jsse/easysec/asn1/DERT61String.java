package com.mi.car.jsse.easysec.asn1;

public class DERT61String extends ASN1T61String {
    public static DERT61String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERT61String)) {
            return (DERT61String) obj;
        }
        if (obj instanceof ASN1T61String) {
            return new DERT61String(((ASN1T61String) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERT61String) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERT61String getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERT61String)) {
            return getInstance((Object) o);
        }
        return new DERT61String(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERT61String(String string) {
        super(string);
    }

    public DERT61String(byte[] string) {
        this(string, true);
    }

    DERT61String(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
