package com.mi.car.jsse.easysec.asn1.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class CertID extends ASN1Object {
    AlgorithmIdentifier hashAlgorithm;
    ASN1OctetString issuerKeyHash;
    ASN1OctetString issuerNameHash;
    ASN1Integer serialNumber;

    public CertID(AlgorithmIdentifier hashAlgorithm2, ASN1OctetString issuerNameHash2, ASN1OctetString issuerKeyHash2, ASN1Integer serialNumber2) {
        this.hashAlgorithm = hashAlgorithm2;
        this.issuerNameHash = issuerNameHash2;
        this.issuerKeyHash = issuerKeyHash2;
        this.serialNumber = serialNumber2;
    }

    private CertID(ASN1Sequence seq) {
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.issuerNameHash = (ASN1OctetString) seq.getObjectAt(1);
        this.issuerKeyHash = (ASN1OctetString) seq.getObjectAt(2);
        this.serialNumber = (ASN1Integer) seq.getObjectAt(3);
    }

    public static CertID getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CertID getInstance(Object obj) {
        if (obj instanceof CertID) {
            return (CertID) obj;
        }
        if (obj != null) {
            return new CertID(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getIssuerNameHash() {
        return this.issuerNameHash;
    }

    public ASN1OctetString getIssuerKeyHash() {
        return this.issuerKeyHash;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.hashAlgorithm);
        v.add(this.issuerNameHash);
        v.add(this.issuerKeyHash);
        v.add(this.serialNumber);
        return new DERSequence(v);
    }
}
