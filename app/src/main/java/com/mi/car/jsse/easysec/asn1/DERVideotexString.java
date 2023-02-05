package com.mi.car.jsse.easysec.asn1;

public class DERVideotexString extends ASN1VideotexString {
    public static DERVideotexString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERVideotexString)) {
            return (DERVideotexString) obj;
        }
        if (obj instanceof ASN1VideotexString) {
            return new DERVideotexString(((ASN1VideotexString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERVideotexString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERVideotexString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERVideotexString)) {
            return getInstance((Object) o);
        }
        return new DERVideotexString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERVideotexString(byte[] octets) {
        this(octets, true);
    }

    DERVideotexString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
