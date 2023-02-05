package com.mi.car.jsse.easysec.asn1.crmf;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.cmp.PKIBody;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;
import java.util.Enumeration;

public class CertTemplate extends ASN1Object {
    private Extensions extensions;
    private X500Name issuer;
    private ASN1BitString issuerUID;
    private SubjectPublicKeyInfo publicKey;
    private ASN1Sequence seq;
    private ASN1Integer serialNumber;
    private AlgorithmIdentifier signingAlg;
    private X500Name subject;
    private ASN1BitString subjectUID;
    private OptionalValidity validity;
    private ASN1Integer version;

    private CertTemplate(ASN1Sequence seq2) {
        this.seq = seq2;
        Enumeration en = seq2.getObjects();
        while (en.hasMoreElements()) {
            ASN1TaggedObject tObj = (ASN1TaggedObject) en.nextElement();
            switch (tObj.getTagNo()) {
                case 0:
                    this.version = ASN1Integer.getInstance(tObj, false);
                    break;
                case 1:
                    this.serialNumber = ASN1Integer.getInstance(tObj, false);
                    break;
                case 2:
                    this.signingAlg = AlgorithmIdentifier.getInstance(tObj, false);
                    break;
                case 3:
                    this.issuer = X500Name.getInstance(tObj, true);
                    break;
                case 4:
                    this.validity = OptionalValidity.getInstance(ASN1Sequence.getInstance(tObj, false));
                    break;
                case 5:
                    this.subject = X500Name.getInstance(tObj, true);
                    break;
                case 6:
                    this.publicKey = SubjectPublicKeyInfo.getInstance(tObj, false);
                    break;
                case 7:
                    this.issuerUID = ASN1BitString.getInstance(tObj, false);
                    break;
                case 8:
                    this.subjectUID = ASN1BitString.getInstance(tObj, false);
                    break;
                case PKIBody.TYPE_KEY_RECOVERY_REQ:
                    this.extensions = Extensions.getInstance(tObj, false);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag: " + tObj.getTagNo());
            }
        }
    }

    public static CertTemplate getInstance(Object o) {
        if (o instanceof CertTemplate) {
            return (CertTemplate) o;
        }
        if (o != null) {
            return new CertTemplate(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getVersion() {
        if (this.version != null) {
            return this.version.intValueExact();
        }
        return -1;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public AlgorithmIdentifier getSigningAlg() {
        return this.signingAlg;
    }

    public X500Name getIssuer() {
        return this.issuer;
    }

    public OptionalValidity getValidity() {
        return this.validity;
    }

    public X500Name getSubject() {
        return this.subject;
    }

    public SubjectPublicKeyInfo getPublicKey() {
        return this.publicKey;
    }

    public ASN1BitString getIssuerUID() {
        return this.issuerUID;
    }

    public ASN1BitString getSubjectUID() {
        return this.subjectUID;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }
}
