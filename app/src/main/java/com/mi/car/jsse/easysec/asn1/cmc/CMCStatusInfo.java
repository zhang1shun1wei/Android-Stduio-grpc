//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Choice;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;

public class CMCStatusInfo extends ASN1Object {
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;
    private final ASN1UTF8String statusString;
    private final CMCStatusInfo.OtherInfo otherInfo;

    CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, ASN1UTF8String statusString, CMCStatusInfo.OtherInfo otherInfo) {
        this.cMCStatus = cMCStatus;
        this.bodyList = bodyList;
        this.statusString = statusString;
        this.otherInfo = otherInfo;
    }

    private CMCStatusInfo(ASN1Sequence seq) {
        if (seq.size() >= 2 && seq.size() <= 4) {
            this.cMCStatus = CMCStatus.getInstance(seq.getObjectAt(0));
            this.bodyList = ASN1Sequence.getInstance(seq.getObjectAt(1));
            if (seq.size() > 3) {
                this.statusString = ASN1UTF8String.getInstance(seq.getObjectAt(2));
                this.otherInfo = CMCStatusInfo.OtherInfo.getInstance(seq.getObjectAt(3));
            } else if (seq.size() > 2) {
                if (seq.getObjectAt(2) instanceof ASN1UTF8String) {
                    this.statusString = ASN1UTF8String.getInstance(seq.getObjectAt(2));
                    this.otherInfo = null;
                } else {
                    this.statusString = null;
                    this.otherInfo = CMCStatusInfo.OtherInfo.getInstance(seq.getObjectAt(2));
                }
            } else {
                this.statusString = null;
                this.otherInfo = null;
            }

        } else {
            throw new IllegalArgumentException("incorrect sequence size");
        }
    }

    public static CMCStatusInfo getInstance(Object o) {
        if (o instanceof CMCStatusInfo) {
            return (CMCStatusInfo)o;
        } else {
            return o != null ? new CMCStatusInfo(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.cMCStatus);
        v.add(this.bodyList);
        if (this.statusString != null) {
            v.add(this.statusString);
        }

        if (this.otherInfo != null) {
            v.add(this.otherInfo);
        }

        return new DERSequence(v);
    }

    public CMCStatus getCMCStatus() {
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

    public boolean hasOtherInfo() {
        return this.otherInfo != null;
    }

    public CMCStatusInfo.OtherInfo getOtherInfo() {
        return this.otherInfo;
    }

    public static class OtherInfo extends ASN1Object implements ASN1Choice {
        private final CMCFailInfo failInfo;
        private final PendInfo pendInfo;

        private static CMCStatusInfo.OtherInfo getInstance(Object obj) {
            if (obj instanceof CMCStatusInfo.OtherInfo) {
                return (CMCStatusInfo.OtherInfo)obj;
            } else {
                if (obj instanceof ASN1Encodable) {
                    ASN1Encodable asn1Value = ((ASN1Encodable)obj).toASN1Primitive();
                    if (asn1Value instanceof ASN1Integer) {
                        return new CMCStatusInfo.OtherInfo(CMCFailInfo.getInstance(asn1Value));
                    }

                    if (asn1Value instanceof ASN1Sequence) {
                        return new CMCStatusInfo.OtherInfo(PendInfo.getInstance(asn1Value));
                    }
                }

                throw new IllegalArgumentException("unknown object in getInstance(): " + obj.getClass().getName());
            }
        }

        OtherInfo(CMCFailInfo failInfo) {
            this(failInfo, (PendInfo)null);
        }

        OtherInfo(PendInfo pendInfo) {
            this((CMCFailInfo)null, pendInfo);
        }

        private OtherInfo(CMCFailInfo failInfo, PendInfo pendInfo) {
            this.failInfo = failInfo;
            this.pendInfo = pendInfo;
        }

        public boolean isFailInfo() {
            return this.failInfo != null;
        }

        public ASN1Primitive toASN1Primitive() {
            return this.pendInfo != null ? this.pendInfo.toASN1Primitive() : this.failInfo.toASN1Primitive();
        }
    }
}