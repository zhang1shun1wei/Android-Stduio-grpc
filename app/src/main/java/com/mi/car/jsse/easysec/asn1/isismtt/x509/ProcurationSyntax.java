package com.mi.car.jsse.easysec.asn1.isismtt.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1PrintableString;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERPrintableString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.DirectoryString;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.asn1.x509.IssuerSerial;
import java.util.Enumeration;

public class ProcurationSyntax extends ASN1Object {
    private IssuerSerial certRef;
    private String country;
    private GeneralName thirdPerson;
    private DirectoryString typeOfSubstitution;

    public static ProcurationSyntax getInstance(Object obj) {
        if (obj == null || (obj instanceof ProcurationSyntax)) {
            return (ProcurationSyntax) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new ProcurationSyntax((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private ProcurationSyntax(ASN1Sequence seq) {
        if (seq.size() < 1 || seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        Enumeration e = seq.getObjects();
        while (e.hasMoreElements()) {
            ASN1TaggedObject o = ASN1TaggedObject.getInstance(e.nextElement());
            switch (o.getTagNo()) {
                case 1:
                    this.country = ASN1PrintableString.getInstance(o, true).getString();
                    break;
                case 2:
                    this.typeOfSubstitution = DirectoryString.getInstance(o, true);
                    break;
                case 3:
                    ASN1Encodable signingFor = o.getObject();
                    if (!(signingFor instanceof ASN1TaggedObject)) {
                        this.certRef = IssuerSerial.getInstance(signingFor);
                        break;
                    } else {
                        this.thirdPerson = GeneralName.getInstance(signingFor);
                        break;
                    }
                default:
                    throw new IllegalArgumentException("Bad tag number: " + o.getTagNo());
            }
        }
    }

    public ProcurationSyntax(String country2, DirectoryString typeOfSubstitution2, IssuerSerial certRef2) {
        this.country = country2;
        this.typeOfSubstitution = typeOfSubstitution2;
        this.thirdPerson = null;
        this.certRef = certRef2;
    }

    public ProcurationSyntax(String country2, DirectoryString typeOfSubstitution2, GeneralName thirdPerson2) {
        this.country = country2;
        this.typeOfSubstitution = typeOfSubstitution2;
        this.thirdPerson = thirdPerson2;
        this.certRef = null;
    }

    public String getCountry() {
        return this.country;
    }

    public DirectoryString getTypeOfSubstitution() {
        return this.typeOfSubstitution;
    }

    public GeneralName getThirdPerson() {
        return this.thirdPerson;
    }

    public IssuerSerial getCertRef() {
        return this.certRef;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(3);
        if (this.country != null) {
            vec.add(new DERTaggedObject(true, 1, new DERPrintableString(this.country, true)));
        }
        if (this.typeOfSubstitution != null) {
            vec.add(new DERTaggedObject(true, 2, this.typeOfSubstitution));
        }
        if (this.thirdPerson != null) {
            vec.add(new DERTaggedObject(true, 3, this.thirdPerson));
        } else {
            vec.add(new DERTaggedObject(true, 3, this.certRef));
        }
        return new DERSequence(vec);
    }
}
