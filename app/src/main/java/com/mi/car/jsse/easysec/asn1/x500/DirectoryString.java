package com.mi.car.jsse.easysec.asn1.x500;

import com.mi.car.jsse.easysec.asn1.ASN1BMPString;
import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.ASN1String;
import com.mi.car.jsse.easysec.asn1.ASN1T61String;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.ASN1UniversalString;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;

public class DirectoryString extends ASN1Object implements ASN1Choice, ASN1String {
    private ASN1String string;

    public static DirectoryString getInstance(Object o) {
        if (o == null || (o instanceof DirectoryString)) {
            return (DirectoryString) o;
        }
        if (o instanceof ASN1T61String) {
            return new DirectoryString((ASN1T61String) o);
        }
        if (o instanceof ASN1PrintableString) {
            return new DirectoryString((ASN1PrintableString) o);
        }
        if (o instanceof ASN1UniversalString) {
            return new DirectoryString((ASN1UniversalString) o);
        }
        if (o instanceof ASN1UTF8String) {
            return new DirectoryString((ASN1UTF8String) o);
        }
        if (o instanceof ASN1BMPString) {
            return new DirectoryString((ASN1BMPString) o);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + o.getClass().getName());
    }

    public static DirectoryString getInstance(ASN1TaggedObject o, boolean explicit) {
        if (explicit) {
            return getInstance(o.getObject());
        }
        throw new IllegalArgumentException("choice item must be explicitly tagged");
    }

    private DirectoryString(ASN1T61String string2) {
        this.string = string2;
    }

    private DirectoryString(ASN1PrintableString string2) {
        this.string = string2;
    }

    private DirectoryString(ASN1UniversalString string2) {
        this.string = string2;
    }

    private DirectoryString(ASN1UTF8String string2) {
        this.string = string2;
    }

    private DirectoryString(ASN1BMPString string2) {
        this.string = string2;
    }

    public DirectoryString(String string2) {
        this.string = new DERUTF8String(string2);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1String
    public String getString() {
        return this.string.getString();
    }

    public String toString() {
        return this.string.getString();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return ((ASN1Encodable) this.string).toASN1Primitive();
    }
}
