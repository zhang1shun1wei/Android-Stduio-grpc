package com.mi.car.jsse.easysec.asn1.esf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;
import java.util.Enumeration;

public class SignerLocation extends ASN1Object {
    private DirectoryString countryName;
    private DirectoryString localityName;
    private ASN1Sequence postalAddress;

    private SignerLocation(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = (ASN1TaggedObject) e.nextElement();
            switch (o.getTagNo()) {
                case 0:
                    this.countryName = DirectoryString.getInstance(o, true);
                    break;
                case 1:
                    this.localityName = DirectoryString.getInstance(o, true);
                    break;
                case 2:
                    if (o.isExplicit()) {
                        this.postalAddress = ASN1Sequence.getInstance(o, true);
                    } else {
                        this.postalAddress = ASN1Sequence.getInstance(o, false);
                    }
                    if (this.postalAddress != null && this.postalAddress.size() > 6) {
                        throw new IllegalArgumentException("postal address must contain less than 6 strings");
                    }
                default:
                    throw new IllegalArgumentException("illegal tag");
            }
        }
    }

    private SignerLocation(DirectoryString countryName2, DirectoryString localityName2, ASN1Sequence postalAddress2) {
        if (postalAddress2 == null || postalAddress2.size() <= 6) {
            this.countryName = countryName2;
            this.localityName = localityName2;
            this.postalAddress = postalAddress2;
            return;
        }
        throw new IllegalArgumentException("postal address must contain less than 6 strings");
    }

    public SignerLocation(DirectoryString countryName2, DirectoryString localityName2, DirectoryString[] postalAddress2) {
        this(countryName2, localityName2, (ASN1Sequence) new DERSequence(postalAddress2));
    }

    public SignerLocation(ASN1UTF8String countryName2, ASN1UTF8String localityName2, ASN1Sequence postalAddress2) {
        this(DirectoryString.getInstance(countryName2), DirectoryString.getInstance(localityName2), postalAddress2);
    }

    public static SignerLocation getInstance(Object obj) {
        if (obj == null || (obj instanceof SignerLocation)) {
            return (SignerLocation) obj;
        }
        return new SignerLocation(ASN1Sequence.getInstance(obj));
    }

    public DirectoryString getCountry() {
        return this.countryName;
    }

    public DirectoryString getLocality() {
        return this.localityName;
    }

    public DirectoryString[] getPostal() {
        if (this.postalAddress == null) {
            return null;
        }
        DirectoryString[] dirStrings = new DirectoryString[this.postalAddress.size()];
        for (int i = 0; i != dirStrings.length; i++) {
            dirStrings[i] = DirectoryString.getInstance(this.postalAddress.getObjectAt(i));
        }
        return dirStrings;
    }

    public DERUTF8String getCountryName() {
        if (this.countryName == null) {
            return null;
        }
        return new DERUTF8String(getCountry().getString());
    }

    public DERUTF8String getLocalityName() {
        if (this.localityName == null) {
            return null;
        }
        return new DERUTF8String(getLocality().getString());
    }

    public ASN1Sequence getPostalAddress() {
        return this.postalAddress;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.countryName != null) {
            v.add(new DERTaggedObject(true, 0, this.countryName));
        }
        if (this.localityName != null) {
            v.add(new DERTaggedObject(true, 1, this.localityName));
        }
        if (this.postalAddress != null) {
            v.add(new DERTaggedObject(true, 2, this.postalAddress));
        }
        return new DERSequence(v);
    }
}
