package com.mi.car.jsse.easysec.asn1;

public class DERUniversalString extends ASN1UniversalString {
    public static DERUniversalString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERUniversalString)) {
            return (DERUniversalString) obj;
        }
        if (obj instanceof ASN1UniversalString) {
            return new DERUniversalString(((ASN1UniversalString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERUniversalString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERUniversalString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERUniversalString)) {
            return getInstance((Object) o);
        }
        return new DERUniversalString(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERUniversalString(byte[] string) {
        this(string, true);
    }

    DERUniversalString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
