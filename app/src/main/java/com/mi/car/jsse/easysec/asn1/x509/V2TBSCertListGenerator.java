package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTCTime;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x500.X500Name;
import java.io.IOException;

public class V2TBSCertListGenerator {
    private static final ASN1Sequence[] reasons = new ASN1Sequence[11];
    private ASN1EncodableVector crlentries = new ASN1EncodableVector();
    private Extensions extensions = null;
    private X500Name issuer;
    private Time nextUpdate = null;
    private AlgorithmIdentifier signature;
    private Time thisUpdate;
    private ASN1Integer version = new ASN1Integer(1);

    static {
        reasons[0] = createReasonExtension(0);
        reasons[1] = createReasonExtension(1);
        reasons[2] = createReasonExtension(2);
        reasons[3] = createReasonExtension(3);
        reasons[4] = createReasonExtension(4);
        reasons[5] = createReasonExtension(5);
        reasons[6] = createReasonExtension(6);
        reasons[7] = createReasonExtension(7);
        reasons[8] = createReasonExtension(8);
        reasons[9] = createReasonExtension(9);
        reasons[10] = createReasonExtension(10);
    }

    public void setSignature(AlgorithmIdentifier signature2) {
        this.signature = signature2;
    }

    public void setIssuer(X509Name issuer2) {
        this.issuer = X500Name.getInstance(issuer2.toASN1Primitive());
    }

    public void setIssuer(X500Name issuer2) {
        this.issuer = issuer2;
    }

    public void setThisUpdate(ASN1UTCTime thisUpdate2) {
        this.thisUpdate = new Time(thisUpdate2);
    }

    public void setNextUpdate(ASN1UTCTime nextUpdate2) {
        this.nextUpdate = new Time(nextUpdate2);
    }

    public void setThisUpdate(Time thisUpdate2) {
        this.thisUpdate = thisUpdate2;
    }

    public void setNextUpdate(Time nextUpdate2) {
        this.nextUpdate = nextUpdate2;
    }

    public void addCRLEntry(ASN1Sequence crlEntry) {
        this.crlentries.add(crlEntry);
    }

    public void addCRLEntry(ASN1Integer userCertificate, ASN1UTCTime revocationDate, int reason) {
        addCRLEntry(userCertificate, new Time(revocationDate), reason);
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, int reason) {
        addCRLEntry(userCertificate, revocationDate, reason, null);
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, int reason, ASN1GeneralizedTime invalidityDate) {
        if (reason != 0) {
            ASN1EncodableVector v = new ASN1EncodableVector(2);
            if (reason >= reasons.length) {
                v.add(createReasonExtension(reason));
            } else if (reason < 0) {
                throw new IllegalArgumentException("invalid reason value: " + reason);
            } else {
                v.add(reasons[reason]);
            }
            if (invalidityDate != null) {
                v.add(createInvalidityDateExtension(invalidityDate));
            }
            internalAddCRLEntry(userCertificate, revocationDate, new DERSequence(v));
        } else if (invalidityDate != null) {
            internalAddCRLEntry(userCertificate, revocationDate, new DERSequence(createInvalidityDateExtension(invalidityDate)));
        } else {
            addCRLEntry(userCertificate, revocationDate, (Extensions) null);
        }
    }

    private void internalAddCRLEntry(ASN1Integer userCertificate, Time revocationDate, ASN1Sequence extensions2) {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(userCertificate);
        v.add(revocationDate);
        if (extensions2 != null) {
            v.add(extensions2);
        }
        addCRLEntry(new DERSequence(v));
    }

    public void addCRLEntry(ASN1Integer userCertificate, Time revocationDate, Extensions extensions2) {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(userCertificate);
        v.add(revocationDate);
        if (extensions2 != null) {
            v.add(extensions2);
        }
        addCRLEntry(new DERSequence(v));
    }

    public void setExtensions(X509Extensions extensions2) {
        setExtensions(Extensions.getInstance(extensions2));
    }

    public void setExtensions(Extensions extensions2) {
        this.extensions = extensions2;
    }

    public TBSCertList generateTBSCertList() {
        if (this.signature == null || this.issuer == null || this.thisUpdate == null) {
            throw new IllegalStateException("Not all mandatory fields set in V2 TBSCertList generator.");
        }
        ASN1EncodableVector v = new ASN1EncodableVector(7);
        v.add(this.version);
        v.add(this.signature);
        v.add(this.issuer);
        v.add(this.thisUpdate);
        if (this.nextUpdate != null) {
            v.add(this.nextUpdate);
        }
        if (this.crlentries.size() != 0) {
            v.add(new DERSequence(this.crlentries));
        }
        if (this.extensions != null) {
            v.add(new DERTaggedObject(0, this.extensions));
        }
        return new TBSCertList(new DERSequence(v));
    }

    private static ASN1Sequence createReasonExtension(int reasonCode) {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        CRLReason crlReason = CRLReason.lookup(reasonCode);
        try {
            v.add(Extension.reasonCode);
            v.add(new DEROctetString(crlReason.getEncoded()));
            return new DERSequence(v);
        } catch (IOException e) {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }
    }

    private static ASN1Sequence createInvalidityDateExtension(ASN1GeneralizedTime invalidityDate) {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        try {
            v.add(Extension.invalidityDate);
            v.add(new DEROctetString(invalidityDate.getEncoded()));
            return new DERSequence(v);
        } catch (IOException e) {
            throw new IllegalArgumentException("error encoding reason: " + e);
        }
    }
}
