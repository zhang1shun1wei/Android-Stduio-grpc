package com.mi.car.jsse.easysec.asn1;

public class DERNumericString extends ASN1NumericString {
    public static DERNumericString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERNumericString)) {
            return (DERNumericString) obj;
        }
        if (obj instanceof ASN1NumericString) {
            return new DERNumericString(((ASN1NumericString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERNumericString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERNumericString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERNumericString)) {
            return getInstance((Object) o);
        }
        return new DERNumericString(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERNumericString(String string) {
        this(string, false);
    }

    public DERNumericString(String string, boolean validate) {
        super(string, validate);
    }

    DERNumericString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
