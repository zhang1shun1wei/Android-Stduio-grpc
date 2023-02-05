package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import java.math.BigInteger;

public class IssuerSerial extends ASN1Object {
    GeneralNames issuer;
    ASN1BitString issuerUID;
    ASN1Integer serial;

    public static IssuerSerial getInstance(Object obj) {
        if (obj instanceof IssuerSerial) {
            return (IssuerSerial) obj;
        }
        if (obj != null) {
            return new IssuerSerial(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static IssuerSerial getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    private IssuerSerial(ASN1Sequence seq) {
        if (seq.size() == 2 || seq.size() == 3) {
            this.issuer = GeneralNames.getInstance(seq.getObjectAt(0));
            this.serial = ASN1Integer.getInstance(seq.getObjectAt(1));
            if (seq.size() == 3) {
                this.issuerUID = DERBitString.getInstance((Object) seq.getObjectAt(2));
                return;
            }
            return;
        }
        throw new IllegalArgumentException("Bad sequence size: " + seq.size());
    }

    public IssuerSerial(X500Name issuer2, BigInteger serial2) {
        this(new GeneralNames(new GeneralName(issuer2)), new ASN1Integer(serial2));
    }

    public IssuerSerial(GeneralNames issuer2, BigInteger serial2) {
        this(issuer2, new ASN1Integer(serial2));
    }

    public IssuerSerial(GeneralNames issuer2, ASN1Integer serial2) {
        this.issuer = issuer2;
        this.serial = serial2;
    }

    public GeneralNames getIssuer() {
        return this.issuer;
    }

    public ASN1Integer getSerial() {
        return this.serial;
    }

    public ASN1BitString getIssuerUID() {
        return this.issuerUID;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.issuer);
        v.add(this.serial);
        if (this.issuerUID != null) {
            v.add(this.issuerUID);
        }
        return new DERSequence(v);
    }
}
