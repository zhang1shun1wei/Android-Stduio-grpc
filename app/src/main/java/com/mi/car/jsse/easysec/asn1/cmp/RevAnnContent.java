//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.crmf.CertId;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;

public class RevAnnContent extends ASN1Object {
    private final PKIStatus status;
    private final CertId certId;
    private final ASN1GeneralizedTime willBeRevokedAt;
    private final ASN1GeneralizedTime badSinceDate;
    private Extensions crlDetails;

    public RevAnnContent(PKIStatus status, CertId certId, ASN1GeneralizedTime willBeRevokedAt, ASN1GeneralizedTime badSinceDate) {
        this(status, certId, willBeRevokedAt, badSinceDate, (Extensions)null);
    }

    public RevAnnContent(PKIStatus status, CertId certId, ASN1GeneralizedTime willBeRevokedAt, ASN1GeneralizedTime badSinceDate, Extensions crlDetails) {
        this.status = status;
        this.certId = certId;
        this.willBeRevokedAt = willBeRevokedAt;
        this.badSinceDate = badSinceDate;
        this.crlDetails = crlDetails;
    }

    private RevAnnContent(ASN1Sequence seq) {
        this.status = PKIStatus.getInstance(seq.getObjectAt(0));
        this.certId = CertId.getInstance(seq.getObjectAt(1));
        this.willBeRevokedAt = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
        this.badSinceDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
        if (seq.size() > 4) {
            this.crlDetails = Extensions.getInstance(seq.getObjectAt(4));
        }

    }

    public static RevAnnContent getInstance(Object o) {
        if (o instanceof RevAnnContent) {
            return (RevAnnContent)o;
        } else {
            return o != null ? new RevAnnContent(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public PKIStatus getStatus() {
        return this.status;
    }

    public CertId getCertId() {
        return this.certId;
    }

    public ASN1GeneralizedTime getWillBeRevokedAt() {
        return this.willBeRevokedAt;
    }

    public ASN1GeneralizedTime getBadSinceDate() {
        return this.badSinceDate;
    }

    public Extensions getCrlDetails() {
        return this.crlDetails;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.status);
        v.add(this.certId);
        v.add(this.willBeRevokedAt);
        v.add(this.badSinceDate);
        if (this.crlDetails != null) {
            v.add(this.crlDetails);
        }

        return new DERSequence(v);
    }
}
