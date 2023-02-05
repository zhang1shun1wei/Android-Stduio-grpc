//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;

public class CMCStatusInfoV2 extends ASN1Object {
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;
    private final ASN1UTF8String statusString;
    private final OtherStatusInfo otherStatusInfo;

    CMCStatusInfoV2(CMCStatus cMCStatus, ASN1Sequence bodyList, ASN1UTF8String statusString, OtherStatusInfo otherStatusInfo) {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherStatusInfo = otherStatusInfo;
    }

    private CMCStatusInfoV2(ASN1Sequence seq) {
        if (seq.size() >= 2 && seq.size() <= 4) {
            this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
            this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));
            if (seq.size() > 2) {
                if (seq.size() == 4) {
                    this.statusString = ASN1UTF8String.getInstance(seq.getObjectAt(2));
                    this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(3));
                } else if (seq.getObjectAt(2) instanceof ASN1UTF8String) {
                    this.statusString = ASN1UTF8String.getInstance(seq.getObjectAt(2));
                    this.otherStatusInfo = null;
                } else {
                    this.statusString = null;
                    this.otherStatusInfo = OtherStatusInfo.getInstance(seq.getObjectAt(2));
                }
            } else {
                this.statusString = null;
                this.otherStatusInfo = null;
            }

        } else {
            throw new IllegalArgumentException("incorrect sequence size");
        }
    }

    public CMCStatus getcMCStatus() {
        return this.cMCStatus;
    }

    public BodyPartID[] getBodyList() {
        return Utils.toBodyPartIDArray(this.bodyList);
    }

    /** @deprecated */
    public DERUTF8String getStatusString() {
        return null != this.statusString && !(this.statusString instanceof DERUTF8String) ? new DERUTF8String(this.statusString.getString()) : (DERUTF8String)this.statusString;
    }

    public ASN1UTF8String getStatusStringUTF8() {
        return this.statusString;
    }

    public OtherStatusInfo getOtherStatusInfo() {
        return this.otherStatusInfo;
    }

    public boolean hasOtherInfo() {
        return this.otherStatusInfo != null;
    }

    public static CMCStatusInfoV2 getInstance(Object o) {
        if (o instanceof CMCStatusInfoV2) {
            return (CMCStatusInfoV2)o;
        } else {
            return o != null ? new CMCStatusInfoV2(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.cMCStatus);
        v.add(this.bodyList);
        if (this.statusString != null) {
            v.add(this.statusString);
        }

        if (this.otherStatusInfo != null) {
            v.add(this.otherStatusInfo);
        }

        return new DERSequence(v);
    }
}