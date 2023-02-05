package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1Set;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.X509Name;
import java.util.Enumeration;

public class CertificationRequestInfo extends ASN1Object {
    ASN1Set attributes;
    X500Name subject;
    SubjectPublicKeyInfo subjectPKInfo;
    ASN1Integer version;

    public static CertificationRequestInfo getInstance(Object obj) {
        if (obj instanceof CertificationRequestInfo) {
            return (CertificationRequestInfo) obj;
        }
        if (obj != null) {
            return new CertificationRequestInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public CertificationRequestInfo(X500Name subject2, SubjectPublicKeyInfo pkInfo, ASN1Set attributes2) {
        this.version = new ASN1Integer(0);
        this.attributes = null;
        if (subject2 == null || pkInfo == null) {
            throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
        }
        validateAttributes(attributes2);
        this.subject = subject2;
        this.subjectPKInfo = pkInfo;
        this.attributes = attributes2;
    }

    public CertificationRequestInfo(X509Name subject2, SubjectPublicKeyInfo pkInfo, ASN1Set attributes2) {
        this(X500Name.getInstance(subject2.toASN1Primitive()), pkInfo, attributes2);
    }

    private CertificationRequestInfo(ASN1Sequence seq) {
        this.version = new ASN1Integer(0);
        this.attributes = null;
        this.version = (ASN1Integer) seq.getObjectAt(0);
        this.subject = X500Name.getInstance(seq.getObjectAt(1));
        this.subjectPKInfo = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(2));
        if (seq.size() > 3) {
            this.attributes = ASN1Set.getInstance((ASN1TaggedObject) seq.getObjectAt(3), false);
        }
        validateAttributes(this.attributes);
        if (this.subject == null || this.version == null || this.subjectPKInfo == null) {
            throw new IllegalArgumentException("Not all mandatory fields set in CertificationRequestInfo generator.");
        }
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.subjectPKInfo;
    }

    public ASN1Set getAttributes() {
        return this.attributes;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.version);
        v.add(this.subject);
        v.add(this.subjectPKInfo);
        if (this.attributes != null) {
            v.add(new DERTaggedObject(false, 0, (ASN1Encodable) this.attributes));
        }
        return new DERSequence(v);
    }

    private static void validateAttributes(ASN1Set attributes2) {
        if (attributes2 != null) {
            Enumeration en = attributes2.getObjects();
            while (en.hasMoreElements()) {
                Attribute attr = Attribute.getInstance(en.nextElement());
                if (attr.getAttrType().equals((ASN1Primitive) PKCSObjectIdentifiers.pkcs_9_at_challengePassword) && attr.getAttrValues().size() != 1) {
                    throw new IllegalArgumentException("challengePassword attribute must have one value");
                }
            }
        }
    }
}
