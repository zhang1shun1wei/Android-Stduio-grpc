package com.mi.car.jsse.easysec.asn1;

public class DERBMPString extends ASN1BMPString {
    public static DERBMPString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERBMPString)) {
            return (DERBMPString) obj;
        }
        if (obj instanceof ASN1BMPString) {
            return new DERBMPString(((ASN1BMPString) obj).string);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERBMPString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERBMPString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERBMPString)) {
            return getInstance((Object) o);
        }
        return new DERBMPString(ASN1OctetString.getInstance(o).getOctets());
    }

    public DERBMPString(String string) {
        super(string);
    }

    DERBMPString(byte[] contents) {
        super(contents);
    }

    DERBMPString(char[] string) {
        super(string);
    }
}
