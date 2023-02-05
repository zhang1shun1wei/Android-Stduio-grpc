package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERPrintableString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class DeclarationOfMajority extends ASN1Object implements ASN1Choice {
    public static final int dateOfBirth = 2;
    public static final int fullAgeAtCountry = 1;
    public static final int notYoungerThan = 0;
    private ASN1TaggedObject declaration;

    public DeclarationOfMajority(int notYoungerThan2) {
        this.declaration = new DERTaggedObject(false, 0, new ASN1Integer((long) notYoungerThan2));
    }

    public DeclarationOfMajority(boolean fullAge, String country) {
        if (country.length() > 2) {
            throw new IllegalArgumentException("country can only be 2 characters");
        } else if (fullAge) {
            this.declaration = new DERTaggedObject(false, 1, new DERSequence(new DERPrintableString(country, true)));
        } else {
            ASN1EncodableVector v = new ASN1EncodableVector(2);
            v.add(ASN1Boolean.FALSE);
            v.add(new DERPrintableString(country, true));
            this.declaration = new DERTaggedObject(false, 1, new DERSequence(v));
        }
    }

    public DeclarationOfMajority(ASN1GeneralizedTime dateOfBirth2) {
        this.declaration = new DERTaggedObject(false, 2, dateOfBirth2);
    }

    public static DeclarationOfMajority getInstance(Object obj) {
        if (obj == null || (obj instanceof DeclarationOfMajority)) {
            return (DeclarationOfMajority) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new DeclarationOfMajority((ASN1TaggedObject) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private DeclarationOfMajority(ASN1TaggedObject o) {
        if (o.getTagNo() > 2) {
            throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
        }
        this.declaration = o;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.declaration;
    }

    public int getType() {
        return this.declaration.getTagNo();
    }

    public int notYoungerThan() {
        if (this.declaration.getTagNo() != 0) {
            return -1;
        }
        return ASN1Integer.getInstance(this.declaration, false).intValueExact();
    }

    public ASN1Sequence fullAgeAtCountry() {
        if (this.declaration.getTagNo() != 1) {
            return null;
        }
        return ASN1Sequence.getInstance(this.declaration, false);
    }

    public ASN1GeneralizedTime getDateOfBirth() {
        if (this.declaration.getTagNo() != 2) {
            return null;
        }
        return ASN1GeneralizedTime.getInstance(this.declaration, false);
    }
}
