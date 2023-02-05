package com.mi.car.jsse.easysec.asn1.dvcs;

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
import com.mi.car.jsse.easysec.asn1.cmp.PKIStatusInfo;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.PolicyInformation;

public class DVCSCertInfo extends ASN1Object {
    private static final int DEFAULT_VERSION = 1;
    private static final int TAG_CERTS = 3;
    private static final int TAG_DV_STATUS = 0;
    private static final int TAG_POLICY = 1;
    private static final int TAG_REQ_SIGNATURE = 2;
    private ASN1Sequence certs;
    private DVCSRequestInformation dvReqInfo;
    private PKIStatusInfo dvStatus;
    private Extensions extensions;
    private DigestInfo messageImprint;
    private PolicyInformation policy;
    private ASN1Set reqSignature;
    private DVCSTime responseTime;
    private ASN1Integer serialNumber;
    private int version = 1;

    public DVCSCertInfo(DVCSRequestInformation dvReqInfo2, DigestInfo messageImprint2, ASN1Integer serialNumber2, DVCSTime responseTime2) {
        this.dvReqInfo = dvReqInfo2;
        this.messageImprint = messageImprint2;
        this.serialNumber = serialNumber2;
        this.responseTime = responseTime2;
    }

    private DVCSCertInfo(ASN1Sequence seq) {
        int i;
        int i2 = 0 + 1;
        ASN1Encodable x = seq.getObjectAt(0);
        try {
            this.version = ASN1Integer.getInstance(x).intValueExact();
            i = i2 + 1;
            try {
                x = seq.getObjectAt(i2);
            } catch (IllegalArgumentException e) {
            }
        } catch (IllegalArgumentException e2) {
            i = i2;
        }
        this.dvReqInfo = DVCSRequestInformation.getInstance(x);
        int i3 = i + 1;
        this.messageImprint = DigestInfo.getInstance(seq.getObjectAt(i));
        int i4 = i3 + 1;
        this.serialNumber = ASN1Integer.getInstance(seq.getObjectAt(i3));
        int i5 = i4 + 1;
        this.responseTime = DVCSTime.getInstance(seq.getObjectAt(i4));
        while (i5 < seq.size()) {
            i5++;
            ASN1Encodable x2 = seq.getObjectAt(i5);
            if (x2 instanceof ASN1TaggedObject) {
                ASN1TaggedObject t = ASN1TaggedObject.getInstance(x2);
                int tagNo = t.getTagNo();
                switch (tagNo) {
                    case 0:
                        this.dvStatus = PKIStatusInfo.getInstance(t, false);
                        continue;
                    case 1:
                        this.policy = PolicyInformation.getInstance(ASN1Sequence.getInstance(t, false));
                        continue;
                    case 2:
                        this.reqSignature = ASN1Set.getInstance(t, false);
                        continue;
                    case 3:
                        this.certs = ASN1Sequence.getInstance(t, false);
                        continue;
                    default:
                        throw new IllegalArgumentException("Unknown tag encountered: " + tagNo);
                }
            } else {
                try {
                    this.extensions = Extensions.getInstance(x2);
                } catch (IllegalArgumentException e3) {
                }
            }
        }
    }

    public static DVCSCertInfo getInstance(Object obj) {
        if (obj instanceof DVCSCertInfo) {
            return (DVCSCertInfo) obj;
        }
        if (obj != null) {
            return new DVCSCertInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static DVCSCertInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(10);
        if (this.version != 1) {
            v.add(new ASN1Integer((long) this.version));
        }
        v.add(this.dvReqInfo);
        v.add(this.messageImprint);
        v.add(this.serialNumber);
        v.add(this.responseTime);
        if (this.dvStatus != null) {
            v.add(new DERTaggedObject(false, 0, this.dvStatus));
        }
        if (this.policy != null) {
            v.add(new DERTaggedObject(false, 1, this.policy));
        }
        if (this.reqSignature != null) {
            v.add(new DERTaggedObject(false, 2, this.reqSignature));
        }
        if (this.certs != null) {
            v.add(new DERTaggedObject(false, 3, this.certs));
        }
        if (this.extensions != null) {
            v.add(this.extensions);
        }
        return new DERSequence(v);
    }

    public String toString() {
        StringBuffer s = new StringBuffer();
        s.append("DVCSCertInfo {\n");
        if (this.version != 1) {
            s.append("version: " + this.version + "\n");
        }
        s.append("dvReqInfo: " + this.dvReqInfo + "\n");
        s.append("messageImprint: " + this.messageImprint + "\n");
        s.append("serialNumber: " + this.serialNumber + "\n");
        s.append("responseTime: " + this.responseTime + "\n");
        if (this.dvStatus != null) {
            s.append("dvStatus: " + this.dvStatus + "\n");
        }
        if (this.policy != null) {
            s.append("policy: " + this.policy + "\n");
        }
        if (this.reqSignature != null) {
            s.append("reqSignature: " + this.reqSignature + "\n");
        }
        if (this.certs != null) {
            s.append("certs: " + this.certs + "\n");
        }
        if (this.extensions != null) {
            s.append("extensions: " + this.extensions + "\n");
        }
        s.append("}\n");
        return s.toString();
    }

    public int getVersion() {
        return this.version;
    }

    private void setVersion(int version2) {
        this.version = version2;
    }

    public DVCSRequestInformation getDvReqInfo() {
        return this.dvReqInfo;
    }

    private void setDvReqInfo(DVCSRequestInformation dvReqInfo2) {
        this.dvReqInfo = dvReqInfo2;
    }

    public DigestInfo getMessageImprint() {
        return this.messageImprint;
    }

    private void setMessageImprint(DigestInfo messageImprint2) {
        this.messageImprint = messageImprint2;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public DVCSTime getResponseTime() {
        return this.responseTime;
    }

    public PKIStatusInfo getDvStatus() {
        return this.dvStatus;
    }

    public PolicyInformation getPolicy() {
        return this.policy;
    }

    public ASN1Set getReqSignature() {
        return this.reqSignature;
    }

    public TargetEtcChain[] getCerts() {
        if (this.certs != null) {
            return TargetEtcChain.arrayFromSequence(this.certs);
        }
        return null;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }
}
