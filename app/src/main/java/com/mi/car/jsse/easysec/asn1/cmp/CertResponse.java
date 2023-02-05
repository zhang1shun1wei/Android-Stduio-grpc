//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class CertResponse extends ASN1Object {
    private final ASN1Integer certReqId;
    private final PKIStatusInfo status;
    private CertifiedKeyPair certifiedKeyPair;
    private ASN1OctetString rspInfo;

    private CertResponse(ASN1Sequence seq) {
        this.certReqId = ASN1Integer.getInstance(seq.getObjectAt(0));
        this.status = PKIStatusInfo.getInstance(seq.getObjectAt(1));
        if (seq.size() >= 3) {
            if (seq.size() == 3) {
                ASN1Encodable o = seq.getObjectAt(2);
                if (o instanceof ASN1OctetString) {
                    this.rspInfo = ASN1OctetString.getInstance(o);
                } else {
                    this.certifiedKeyPair = CertifiedKeyPair.getInstance(o);
                }
            } else {
                this.certifiedKeyPair = CertifiedKeyPair.getInstance(seq.getObjectAt(2));
                this.rspInfo = ASN1OctetString.getInstance(seq.getObjectAt(3));
            }
        }

    }

    public CertResponse(ASN1Integer certReqId, PKIStatusInfo status) {
        this(certReqId, status, (CertifiedKeyPair)null, (ASN1OctetString)null);
    }

    public CertResponse(ASN1Integer certReqId, PKIStatusInfo status, CertifiedKeyPair certifiedKeyPair, ASN1OctetString rspInfo) {
        if (certReqId == null) {
            throw new IllegalArgumentException("'certReqId' cannot be null");
        } else if (status == null) {
            throw new IllegalArgumentException("'status' cannot be null");
        } else {
            this.certReqId = certReqId;
            this.status = status;
            this.certifiedKeyPair = certifiedKeyPair;
            this.rspInfo = rspInfo;
        }
    }

    public static CertResponse getInstance(Object o) {
        if (o instanceof CertResponse) {
            return (CertResponse)o;
        } else {
            return o != null ? new CertResponse(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Integer getCertReqId() {
        return this.certReqId;
    }

    public PKIStatusInfo getStatus() {
        return this.status;
    }

    public CertifiedKeyPair getCertifiedKeyPair() {
        return this.certifiedKeyPair;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.certReqId);
        v.add(this.status);
        if (this.certifiedKeyPair != null) {
            v.add(this.certifiedKeyPair);
        }

        if (this.rspInfo != null) {
            v.add(this.rspInfo);
        }

        return new DERSequence(v);
    }
}