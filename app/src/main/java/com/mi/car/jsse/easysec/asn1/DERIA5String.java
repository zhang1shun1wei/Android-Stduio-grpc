package com.mi.car.jsse.easysec.asn1;

public class DERIA5String extends ASN1IA5String {
    public static DERIA5String getInstance(Object obj) {
        if (obj == null || (obj instanceof DERIA5String)) {
            return (DERIA5String) obj;
        }
        if (obj instanceof ASN1IA5String) {
            return new DERIA5String(((ASN1IA5String) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERIA5String) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERIA5String getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERIA5String)) {
            return getInstance((Object) o);
        }
        return new DERIA5String(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERIA5String(String string) {
        this(string, false);
    }

    public DERIA5String(String string, boolean validate) {
        super(string, validate);
    }

    DERIA5String(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
