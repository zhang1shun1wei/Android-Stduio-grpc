//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.crmf.CertTemplate;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.X509Extensions;

public class RevDetails extends ASN1Object {
    private final CertTemplate certDetails;
    private Extensions crlEntryDetails;

    private RevDetails(ASN1Sequence seq) {
        this.certDetails = CertTemplate.getInstance(seq.getObjectAt(0));
        if (seq.size() > 1) {
            this.crlEntryDetails = Extensions.getInstance(seq.getObjectAt(1));
        }

    }

    public RevDetails(CertTemplate certDetails) {
        this.certDetails = certDetails;
    }

    /** @deprecated */
    public RevDetails(CertTemplate certDetails, X509Extensions crlEntryDetails) {
        this.certDetails = certDetails;
        this.crlEntryDetails = Extensions.getInstance(crlEntryDetails.toASN1Primitive());
    }

    public RevDetails(CertTemplate certDetails, Extensions crlEntryDetails) {
        this.certDetails = certDetails;
        this.crlEntryDetails = crlEntryDetails;
    }

    public static RevDetails getInstance(Object o) {
        if (o instanceof RevDetails) {
            return (RevDetails)o;
        } else {
            return o != null ? new RevDetails(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public CertTemplate getCertDetails() {
        return this.certDetails;
    }

    public Extensions getCrlEntryDetails() {
        return this.crlEntryDetails;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.certDetails);
        if (this.crlEntryDetails != null) {
            v.add(this.crlEntryDetails);
        }

        return new DERSequence(v);
    }
}
