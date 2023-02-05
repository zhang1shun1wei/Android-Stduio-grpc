package com.mi.car.jsse.easysec.asn1;

public class DERGraphicString extends ASN1GraphicString {
    public static DERGraphicString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERGraphicString)) {
            return (DERGraphicString) obj;
        }
        if (obj instanceof ASN1GraphicString) {
            return new DERGraphicString(((ASN1GraphicString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERGraphicString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERGraphicString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERGraphicString)) {
            return getInstance((Object) o);
        }
        return new DERGraphicString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERGraphicString(byte[] octets) {
        this(octets, true);
    }

    DERGraphicString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
