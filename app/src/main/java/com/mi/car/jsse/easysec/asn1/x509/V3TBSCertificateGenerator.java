package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1UTCTime;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;

public class V3TBSCertificateGenerator {
    private boolean altNamePresentAndCritical;
    Time endDate;
    Extensions extensions;
    X500Name issuer;
    private DERBitString issuerUniqueID;
    ASN1Integer serialNumber;
    AlgorithmIdentifier signature;
    Time startDate;
    X500Name subject;
    SubjectPublicKeyInfo subjectPublicKeyInfo;
    private DERBitString subjectUniqueID;
    DERTaggedObject version = new DERTaggedObject(true, 0, (ASN1Encodable) new ASN1Integer(2));

    public void setSerialNumber(ASN1Integer serialNumber2) {
        this.serialNumber = serialNumber2;
    }

    public void setSignature(AlgorithmIdentifier signature2) {
        this.signature = signature2;
    }

    public void setIssuer(X509Name issuer2) {
        this.issuer = X500Name.getInstance(issuer2);
    }

    public void setIssuer(X500Name issuer2) {
        this.issuer = issuer2;
    }

    public void setStartDate(ASN1UTCTime startDate2) {
        this.startDate = new Time(startDate2);
    }

    public void setStartDate(Time startDate2) {
        this.startDate = startDate2;
    }

    public void setEndDate(ASN1UTCTime endDate2) {
        this.endDate = new Time(endDate2);
    }

    public void setEndDate(Time endDate2) {
        this.endDate = endDate2;
    }

    public void setSubject(X509Name subject2) {
        this.subject = X500Name.getInstance(subject2.toASN1Primitive());
    }

    public void setSubject(X500Name subject2) {
        this.subject = subject2;
    }

    public void setIssuerUniqueID(DERBitString uniqueID) {
        this.issuerUniqueID = uniqueID;
    }

    public void setSubjectUniqueID(DERBitString uniqueID) {
        this.subjectUniqueID = uniqueID;
    }

    public void setSubjectPublicKeyInfo(SubjectPublicKeyInfo pubKeyInfo) {
        this.subjectPublicKeyInfo = pubKeyInfo;
    }

    public void setExtensions(X509Extensions extensions2) {
        setExtensions(Extensions.getInstance(extensions2));
    }

    public void setExtensions(Extensions extensions2) {
        Extension altName;
        this.extensions = extensions2;
        if (extensions2 != null && (altName = extensions2.getExtension(Extension.subjectAlternativeName)) != null && altName.isCritical()) {
            this.altNamePresentAndCritical = true;
        }
    }

    public TBSCertificate generateTBSCertificate() {
        if (this.serialNumber == null || this.signature == null || this.issuer == null || this.startDate == null || this.endDate == null || ((this.subject == null && !this.altNamePresentAndCritical) || this.subjectPublicKeyInfo == null)) {
            throw new IllegalStateException("not all mandatory fields set in V3 TBScertificate generator");
        }
        ASN1EncodableVector v = new ASN1EncodableVector(10);
        v.add(this.version);
        v.add(this.serialNumber);
        v.add(this.signature);
        v.add(this.issuer);
        ASN1EncodableVector validity = new ASN1EncodableVector(2);
        validity.add(this.startDate);
        validity.add(this.endDate);
        v.add(new DERSequence(validity));
        if (this.subject != null) {
            v.add(this.subject);
        } else {
            v.add(new DERSequence());
        }
        v.add(this.subjectPublicKeyInfo);
        if (this.issuerUniqueID != null) {
            v.add(new DERTaggedObject(false, 1, (ASN1Encodable) this.issuerUniqueID));
        }
        if (this.subjectUniqueID != null) {
            v.add(new DERTaggedObject(false, 2, (ASN1Encodable) this.subjectUniqueID));
        }
        if (this.extensions != null) {
            v.add(new DERTaggedObject(true, 3, (ASN1Encodable) this.extensions));
        }
        return TBSCertificate.getInstance(new DERSequence(v));
    }
}
