package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class CertificationRequest extends ASN1Object {
    protected CertificationRequestInfo reqInfo = null;
    protected AlgorithmIdentifier sigAlgId = null;
    protected DERBitString sigBits = null;

    public static CertificationRequest getInstance(Object o) {
        if (o instanceof CertificationRequest) {
            return (CertificationRequest) o;
        }
        if (o != null) {
            return new CertificationRequest(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    protected CertificationRequest() {
    }

    public CertificationRequest(CertificationRequestInfo requestInfo, AlgorithmIdentifier algorithm, DERBitString signature) {
        this.reqInfo = requestInfo;
        this.sigAlgId = algorithm;
        this.sigBits = signature;
    }

    public CertificationRequest(ASN1Sequence seq) {
        this.reqInfo = CertificationRequestInfo.getInstance(seq.getObjectAt(0));
        this.sigAlgId = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.sigBits = (DERBitString) seq.getObjectAt(2);
    }

    public CertificationRequestInfo getCertificationRequestInfo() {
        return this.reqInfo;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.sigAlgId;
    }

    public DERBitString getSignature() {
        return this.sigBits;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.reqInfo);
        v.add(this.sigAlgId);
        v.add(this.sigBits);
        return new DERSequence(v);
    }
}
