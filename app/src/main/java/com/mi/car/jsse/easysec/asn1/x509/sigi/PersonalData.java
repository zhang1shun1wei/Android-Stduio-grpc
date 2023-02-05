package com.mi.car.jsse.easysec.asn1.x509.sigi;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERPrintableString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;
import java.math.BigInteger;
import java.util.Enumeration;

public class PersonalData extends ASN1Object {
    private ASN1GeneralizedTime dateOfBirth;
    private String gender;
    private BigInteger nameDistinguisher;
    private NameOrPseudonym nameOrPseudonym;
    private DirectoryString placeOfBirth;
    private DirectoryString postalAddress;

    public static PersonalData getInstance(Object obj) {
        if (obj == null || (obj instanceof PersonalData)) {
            return (PersonalData) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new PersonalData((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private PersonalData(ASN1Sequence seq) {
        if (seq.size() < 1) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        this.nameOrPseudonym = NameOrPseudonym.getInstance(e.nextElement());
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 0:
                    this.nameDistinguisher = ASN1Integer.getInstance(o, false).getValue();
                    break;
                case 1:
                    this.dateOfBirth = ASN1GeneralizedTime.getInstance(o, false);
                    break;
                case 2:
                    this.placeOfBirth = DirectoryString.getInstance(o, true);
                    break;
                case 3:
                    this.gender = ASN1PrintableString.getInstance(o, false).getString();
                    break;
                case 4:
                    this.postalAddress = DirectoryString.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    public PersonalData(NameOrPseudonym nameOrPseudonym2, BigInteger nameDistinguisher2, ASN1GeneralizedTime dateOfBirth2, DirectoryString placeOfBirth2, String gender2, DirectoryString postalAddress2) {
        this.nameOrPseudonym = nameOrPseudonym2;
        this.dateOfBirth = dateOfBirth2;
        this.gender = gender2;
        this.nameDistinguisher = nameDistinguisher2;
        this.postalAddress = postalAddress2;
        this.placeOfBirth = placeOfBirth2;
    }

    public NameOrPseudonym getNameOrPseudonym() {
        return this.nameOrPseudonym;
    }

    public BigInteger getNameDistinguisher() {
        return this.nameDistinguisher;
    }

    public ASN1GeneralizedTime getDateOfBirth() {
        return this.dateOfBirth;
    }

    public DirectoryString getPlaceOfBirth() {
        return this.placeOfBirth;
    }

    public String getGender() {
        return this.gender;
    }

    public DirectoryString getPostalAddress() {
        return this.postalAddress;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(6);
        vec.add(this.nameOrPseudonym);
        if (this.nameDistinguisher != null) {
            vec.add(new DERTaggedObject(false, 0, (ASN1Encodable) new ASN1Integer(this.nameDistinguisher)));
        }
        if (this.dateOfBirth != null) {
            vec.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.dateOfBirth));
        }
        if (this.placeOfBirth != null) {
            vec.add(new DERTaggedObject(true, 2, (ASN1Encodable) this.placeOfBirth));
        }
        if (this.gender != null) {
            vec.add(new DERTaggedObject(false, 3, (ASN1Encodable) new DERPrintableString(this.gender, true)));
        }
        if (this.postalAddress != null) {
            vec.add(new DERTaggedObject(true, 4, (ASN1Encodable) this.postalAddress));
        }
        return new DERSequence(vec);
    }
}
