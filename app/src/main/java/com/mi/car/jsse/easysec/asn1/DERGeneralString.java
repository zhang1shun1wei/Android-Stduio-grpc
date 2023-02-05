package com.mi.car.jsse.easysec.asn1;

public class DERGeneralString extends ASN1GeneralString {
    public static DERGeneralString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGeneralString)) {
            return (DERGeneralString) obj;
        }
        if (obj instanceof ASN1GeneralString) {
            return new DERGeneralString(((ASN1GeneralString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERGeneralString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERGeneralString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERGeneralString)) {
            return getInstance((Object) o);
        }
        return new DERGeneralString(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERGeneralString(String string) {
        super(string);
    }

    DERGeneralString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
