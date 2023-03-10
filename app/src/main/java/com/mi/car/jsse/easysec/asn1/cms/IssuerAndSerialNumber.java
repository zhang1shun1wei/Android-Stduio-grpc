//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;
import com.mi.car.jsse.easysec.asn1.x509.X509CertificateStructure;
import com.mi.car.jsse.easysec.asn1.x509.X509Name;
import java.math.BigInteger;

public class IssuerAndSerialNumber extends ASN1Object {
    private X500Name name;
    private ASN1Integer serialNumber;

    public static IssuerAndSerialNumber getInstance(Object obj) {
        if (obj instanceof IssuerAndSerialNumber) {
            return (IssuerAndSerialNumber)obj;
        } else {
            return obj != null ? new IssuerAndSerialNumber(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    /** @deprecated */
    public IssuerAndSerialNumber(ASN1Sequence seq) {
        this.name = X500Name.getInstance(seq.getObjectAt(0));
        this.serialNumber = (ASN1Integer)seq.getObjectAt(1);
    }

    public IssuerAndSerialNumber(Certificate certificate) {
        this.name = certificate.getIssuer();
        this.serialNumber = certificate.getSerialNumber();
    }

    /** @deprecated */
    public IssuerAndSerialNumber(X509CertificateStructure certificate) {
        this.name = certificate.getIssuer();
        this.serialNumber = certificate.getSerialNumber();
    }

    public IssuerAndSerialNumber(X500Name name, BigInteger serialNumber) {
        this.name = name;
        this.serialNumber = new ASN1Integer(serialNumber);
    }

    /** @deprecated */
    public IssuerAndSerialNumber(X509Name name, BigInteger serialNumber) {
        this.name = X500Name.getInstance(name);
        this.serialNumber = new ASN1Integer(serialNumber);
    }

    /** @deprecated */
    public IssuerAndSerialNumber(X509Name name, ASN1Integer serialNumber) {
        this.name = X500Name.getInstance(name);
        this.serialNumber = serialNumber;
    }

    public X500Name getName() {
        return this.name;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.name);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
