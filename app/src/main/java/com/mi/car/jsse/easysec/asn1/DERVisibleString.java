package com.mi.car.jsse.easysec.asn1;

public class DERVisibleString extends ASN1VisibleString {
    public static DERVisibleString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERVisibleString)) {
            return (DERVisibleString) obj;
        }
        if (obj instanceof ASN1VisibleString) {
            return new DERVisibleString(((ASN1VisibleString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERVisibleString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERVisibleString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERVisibleString)) {
            return getInstance((Object) o);
        }
        return new DERVisibleString(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERVisibleString(String string) {
        super(string);
    }

    DERVisibleString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
