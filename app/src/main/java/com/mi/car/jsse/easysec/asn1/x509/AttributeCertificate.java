package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class AttributeCertificate extends ASN1Object {
    AttributeCertificateInfo acinfo;
    AlgorithmIdentifier signatureAlgorithm;
    ASN1BitString signatureValue;

    public static AttributeCertificate getInstance(Object obj) {
        if (obj instanceof AttributeCertificate) {
            return (AttributeCertificate) obj;
        }
        if (obj != null) {
            return new AttributeCertificate(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public AttributeCertificate(AttributeCertificateInfo acinfo2, AlgorithmIdentifier signatureAlgorithm2, DERBitString signatureValue2) {
        this.acinfo = acinfo2;
        this.signatureAlgorithm = signatureAlgorithm2;
        this.signatureValue = signatureValue2;
    }

    private AttributeCertificate(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.acinfo = AttributeCertificateInfo.getInstance(seq.getObjectAt(0));
        this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.signatureValue = DERBitString.getInstance((Object) seq.getObjectAt(2));
    }

    public AttributeCertificateInfo getAcinfo() {
        return this.acinfo;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public ASN1BitString getSignatureValue() {
        return this.signatureValue;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.acinfo);
        v.add(this.signatureAlgorithm);
        v.add(this.signatureValue);
        return new DERSequence(v);
    }
}
