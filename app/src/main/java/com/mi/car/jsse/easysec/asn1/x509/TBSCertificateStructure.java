package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;

public class TBSCertificateStructure extends ASN1Object implements X509ObjectIdentifiers, PKCSObjectIdentifiers {
    Time endDate;
    X509Extensions extensions;
    X500Name issuer;
    ASN1BitString issuerUniqueId;
    ASN1Sequence seq;
    ASN1Integer serialNumber;
    AlgorithmIdentifier signature;
    Time startDate;
    X500Name subject;
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    ASN1BitString subjectUniqueId;
    ASN1Integer version;

    public static TBSCertificateStructure getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static TBSCertificateStructure getInstance(Object obj) {
        if (obj instanceof TBSCertificateStructure) {
            return (TBSCertificateStructure) obj;
        }
        if (obj != null) {
            return new TBSCertificateStructure(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public TBSCertificateStructure(ASN1Sequence seq2) {
        int seqStart = 0;
        this.seq = seq2;
        if (seq2.getObjectAt(0) instanceof ASN1TaggedObject) {
            this.version = ASN1Integer.getInstance((ASN1TaggedObject) seq2.getObjectAt(0), true);
        } else {
            seqStart = -1;
            this.version = new ASN1Integer(0);
        }
        this.serialNumber = ASN1Integer.getInstance(seq2.getObjectAt(seqStart + 1));
        this.signature = AlgorithmIdentifier.getInstance(seq2.getObjectAt(seqStart + 2));
        this.issuer = X500Name.getInstance(seq2.getObjectAt(seqStart + 3));
        ASN1Sequence dates = (ASN1Sequence) seq2.getObjectAt(seqStart + 4);
        this.startDate = Time.getInstance(dates.getObjectAt(0));
        this.endDate = Time.getInstance(dates.getObjectAt(1));
        this.subject = X500Name.getInstance(seq2.getObjectAt(seqStart + 5));
        this.subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq2.getObjectAt(seqStart + 6));
        for (int extras = (seq2.size() - (seqStart + 6)) - 1; extras > 0; extras--) {
            ASN1TaggedObject extra = ASN1TaggedObject.getInstance(seq2.getObjectAt(seqStart + 6 + extras));
            switch (extra.getTagNo()) {
                case 1:
                    this.issuerUniqueId = ASN1BitString.getInstance(extra, false);
                    break;
                case 2:
                    this.subjectUniqueId = ASN1BitString.getInstance(extra, false);
                    break;
                case 3:
                    this.extensions = X509Extensions.getInstance(extra);
                    break;
            }
        }
    }

    public int getVersion() {
        return this.version.intValueExact() + 1;
    }

    public ASN1Integer getVersionNumber() {
        return this.version;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public AlgorithmIdentifier getSignature() {
        return this.signature;
    }

    public X500Name getIssuer() {
        return this.issuer;
    }

    public Time getStartDate() {
        return this.startDate;
    }

    public Time getEndDate() {
        return this.endDate;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.subjectPublicKeyInfo;
    }

    public ASN1BitString getIssuerUniqueId() {
        return this.issuerUniqueId;
    }

    public ASN1BitString getSubjectUniqueId() {
        return this.subjectUniqueId;
    }

    public X509Extensions getExtensions() {
        return this.extensions;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }
}
