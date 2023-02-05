package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.math.BigInteger;

public class CertId extends ASN1Object {
    private GeneralName issuer;
    private ASN1Integer serialNumber;

    private CertId(ASN1Sequence seq) {
        this.issuer = GeneralName.getInstance(seq.getObjectAt(0));
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(1));
    }

    public static CertId getInstance(Object o) {
        if (o instanceof CertId) {
            return (CertId) o;
        }
        if (o != null) {
            return new CertId(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public static CertId getInstance(ASN1TaggedObject obj, boolean isExplicit) {
        return getInstance(ASN1Sequence.getInstance(obj, isExplicit));
    }

    public CertId(GeneralName issuer2, BigInteger serialNumber2) {
        this(issuer2, new ASN1Integer(serialNumber2));
    }

    public CertId(GeneralName issuer2, ASN1Integer serialNumber2) {
        this.issuer = issuer2;
        this.serialNumber = serialNumber2;
    }

    public GeneralName getIssuer() {
        return this.issuer;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.issuer);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
