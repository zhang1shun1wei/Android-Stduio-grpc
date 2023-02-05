package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERSet;

public class V2AttributeCertificateInfoGenerator {
    private ASN1EncodableVector attributes = new ASN1EncodableVector();
    private ASN1GeneralizedTime endDate;
    private Extensions extensions;
    private Holder holder;
    private AttCertIssuer issuer;
    private DERBitString issuerUniqueID;
    private ASN1Integer serialNumber;
    private AlgorithmIdentifier signature;
    private ASN1GeneralizedTime startDate;
    private ASN1Integer version = new ASN1Integer(1);

    public void setHolder(Holder holder2) {
        this.holder = holder2;
    }

    public void addAttribute(String oid, ASN1Encodable value) {
        this.attributes.add(new Attribute(new ASN1ObjectIdentifier(oid), new DERSet(value)));
    }

    public void addAttribute(Attribute attribute) {
        this.attributes.add(attribute);
    }

    public void setSerialNumber(ASN1Integer serialNumber2) {
        this.serialNumber = serialNumber2;
    }

    public void setSignature(AlgorithmIdentifier signature2) {
        this.signature = signature2;
    }

    public void setIssuer(AttCertIssuer issuer2) {
        this.issuer = issuer2;
    }

    public void setStartDate(ASN1GeneralizedTime startDate2) {
        this.startDate = startDate2;
    }

    public void setEndDate(ASN1GeneralizedTime endDate2) {
        this.endDate = endDate2;
    }

    public void setIssuerUniqueID(DERBitString issuerUniqueID2) {
        this.issuerUniqueID = issuerUniqueID2;
    }

    public void setExtensions(X509Extensions extensions2) {
        this.extensions = Extensions.getInstance(extensions2.toASN1Primitive());
    }

    public void setExtensions(Extensions extensions2) {
        this.extensions = extensions2;
    }

    public AttributeCertificateInfo generateAttributeCertificateInfo() {
        if (this.serialNumber == null || this.signature == null || this.issuer == null || this.startDate == null || this.endDate == null || this.holder == null || this.attributes == null) {
            throw new IllegalStateException("not all mandatory fields set in V2 AttributeCertificateInfo generator");
        }
        ASN1EncodableVector v = new ASN1EncodableVector(9);
        v.add(this.version);
        v.add(this.holder);
        v.add(this.issuer);
        v.add(this.signature);
        v.add(this.serialNumber);
        v.add(new AttCertValidityPeriod(this.startDate, this.endDate));
        v.add(new DERSequence(this.attributes));
        if (this.issuerUniqueID != null) {
            v.add(this.issuerUniqueID);
        }
        if (this.extensions != null) {
            v.add(this.extensions);
        }
        return AttributeCertificateInfo.getInstance(new DERSequence(v));
    }
}
