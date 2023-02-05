//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.io.IOException;
import java.math.BigInteger;

public class CertificationRequest extends ASN1Object {
    private static final ASN1Integer ZERO = new ASN1Integer(0L);
    private final CertificationRequest.CertificationRequestInfo certificationRequestInfo;
    private final AlgorithmIdentifier signatureAlgorithm;
    private final ASN1BitString signature;

    public CertificationRequest(X500Name subject, AlgorithmIdentifier subjectPublicAlgorithm, ASN1BitString subjectPublicKey, ASN1Set attributes, AlgorithmIdentifier signatureAlgorithm, ASN1BitString signature) {
        this.certificationRequestInfo = new CertificationRequest.CertificationRequestInfo(subject, subjectPublicAlgorithm, subjectPublicKey, attributes);
        this.signatureAlgorithm = signatureAlgorithm;
        this.signature = signature;
    }

    private CertificationRequest(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.certificationRequestInfo = new CertificationRequest.CertificationRequestInfo(ASN1Sequence.getInstance(seq.getObjectAt(0)));
            this.signatureAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.signature = DERBitString.getInstance(seq.getObjectAt(2));
        }
    }

    public static CertificationRequest getInstance(Object o) {
        if (o instanceof CertificationRequest) {
            return (CertificationRequest)o;
        } else {
            return o != null ? new CertificationRequest(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public BigInteger getVersion() {
        return this.certificationRequestInfo.getVersion().getValue();
    }

    public X500Name getSubject() {
        return this.certificationRequestInfo.getSubject();
    }

    public ASN1Set getAttributes() {
        return this.certificationRequestInfo.getAttributes();
    }

    public AlgorithmIdentifier getSubjectPublicKeyAlgorithm() {
        return AlgorithmIdentifier.getInstance(this.certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(0));
    }

    public ASN1BitString getSubjectPublicKey() {
        return DERBitString.getInstance(this.certificationRequestInfo.getSubjectPublicKeyInfo().getObjectAt(1));
    }

    public ASN1Primitive parsePublicKey() throws IOException {
        return ASN1Primitive.fromByteArray(this.getSubjectPublicKey().getOctets());
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    public ASN1BitString getSignature() {
        return this.signature;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.certificationRequestInfo);
        v.add(this.signatureAlgorithm);
        v.add(this.signature);
        return new DERSequence(v);
    }

    private class CertificationRequestInfo extends ASN1Object {
        private final ASN1Integer version;
        private final X500Name subject;
        private final ASN1Sequence subjectPublicKeyInfo;
        private final ASN1Set attributes;

        private CertificationRequestInfo(ASN1Sequence seq) {
            if (seq.size() != 4) {
                throw new IllegalArgumentException("incorrect sequence size for CertificationRequestInfo");
            } else {
                this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
                this.subject = X500Name.getInstance(seq.getObjectAt(1));
                this.subjectPublicKeyInfo = ASN1Sequence.getInstance(seq.getObjectAt(2));
                if (this.subjectPublicKeyInfo.size() != 2) {
                    throw new IllegalArgumentException("incorrect subjectPublicKeyInfo size for CertificationRequestInfo");
                } else {
                    ASN1TaggedObject tagobj = (ASN1TaggedObject)seq.getObjectAt(3);
                    if (tagobj.getTagNo() != 0) {
                        throw new IllegalArgumentException("incorrect tag number on attributes for CertificationRequestInfo");
                    } else {
                        this.attributes = ASN1Set.getInstance(tagobj, false);
                    }
                }
            }
        }

        private CertificationRequestInfo(X500Name subject, AlgorithmIdentifier algorithm, ASN1BitString subjectPublicKey, ASN1Set attributes) {
            this.version = CertificationRequest.ZERO;
            this.subject = subject;
            this.subjectPublicKeyInfo = new DERSequence(new ASN1Encodable[]{algorithm, subjectPublicKey});
            this.attributes = attributes;
        }

        private ASN1Integer getVersion() {
            return this.version;
        }

        private X500Name getSubject() {
            return this.subject;
        }

        private ASN1Sequence getSubjectPublicKeyInfo() {
            return this.subjectPublicKeyInfo;
        }

        private ASN1Set getAttributes() {
            return this.attributes;
        }

        public ASN1Primitive toASN1Primitive() {
            ASN1EncodableVector v = new ASN1EncodableVector(4);
            v.add(this.version);
            v.add(this.subject);
            v.add(this.subjectPublicKeyInfo);
            v.add(new DERTaggedObject(false, 0, this.attributes));
            return new DERSequence(v);
        }
    }
}