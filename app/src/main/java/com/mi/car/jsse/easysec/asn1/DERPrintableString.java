package com.mi.car.jsse.easysec.asn1;

public class DERPrintableString extends ASN1PrintableString {
    public static DERPrintableString getInstance(Object obj) {
        if (obj == null || (obj instanceof DERPrintableString)) {
            return (DERPrintableString) obj;
        }
        if (obj instanceof ASN1PrintableString) {
            return new DERPrintableString(((ASN1PrintableString) obj).contents, false);
        }
        if (obj instanceof byte[]) {
            try {
                return (DERPrintableString) fromByteArray((byte[]) obj);
            } catch (Exception e) {
                throw new IllegalArgumentException("encoding error in getInstance: " + e.toString());
            }
        } else {
            throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
        }
    }

    public static DERPrintableString getInstance(ASN1TaggedObject obj, boolean explicit) {
        ASN1Primitive o = obj.getObject();
        if (explicit || (o instanceof DERPrintableString)) {
            return getInstance((Object) o);
        }
        return new DERPrintableString(ASN1OctetString.getInstance(o).getOctets(), true);
    }

    public DERPrintableString(String string) {
        this(string, false);
    }

    public DERPrintableString(String string, boolean validate) {
        super(string, validate);
    }

    DERPrintableString(byte[] contents, boolean clone) {
        super(contents, clone);
    }
}
