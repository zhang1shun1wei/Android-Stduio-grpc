package com.mi.car.jsse.easysec.asn1.x509.qualified;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.DERPrintableString;

public class Iso4217CurrencyCode extends ASN1Object implements ASN1Choice {
    final int ALPHABETIC_MAXSIZE = 3;
    final int NUMERIC_MAXSIZE = 999;
    final int NUMERIC_MINSIZE = 1;
    int numeric;
    ASN1Encodable obj;

    public static Iso4217CurrencyCode getInstance(Object obj2) {
        if (obj2 == null || (obj2 instanceof Iso4217CurrencyCode)) {
            return (Iso4217CurrencyCode) obj2;
        }
        if (obj2 instanceof ASN1Integer) {
            return new Iso4217CurrencyCode(ASN1Integer.getInstance(obj2).intValueExact());
        }
        if (obj2 instanceof ASN1PrintableString) {
            return new Iso4217CurrencyCode(ASN1PrintableString.getInstance(obj2).getString());
        }
        throw new IllegalArgumentException("unknown object in getInstance");
    }

    public Iso4217CurrencyCode(int numeric2) {
        if (numeric2 > 999 || numeric2 < 1) {
            throw new IllegalArgumentException("wrong size in numeric code : not in (1..999)");
        }
        this.obj = new ASN1Integer((long) numeric2);
    }

    public Iso4217CurrencyCode(String alphabetic) {
        if (alphabetic.length() > 3) {
            throw new IllegalArgumentException("wrong size in alphabetic code : max size is 3");
        }
        this.obj = new DERPrintableString(alphabetic);
    }

    public boolean isAlphabetic() {
        return this.obj instanceof ASN1PrintableString;
    }

    public String getAlphabetic() {
        return ((ASN1PrintableString) this.obj).getString();
    }

    public int getNumeric() {
        return ((ASN1Integer) this.obj).intValueExact();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.obj.toASN1Primitive();
    }
}
