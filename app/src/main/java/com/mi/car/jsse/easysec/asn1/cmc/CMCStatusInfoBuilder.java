//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;
import com.mi.car.jsse.easysec.asn1.cmc.CMCStatusInfo.OtherInfo;

public class CMCStatusInfoBuilder {
    private final CMCStatus cMCStatus;
    private final ASN1Sequence bodyList;
    private ASN1UTF8String statusString;
    private OtherInfo otherInfo;

    public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID bodyPartID) {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyPartID);
    }

    public CMCStatusInfoBuilder(CMCStatus cMCStatus, BodyPartID[] bodyList) {
        this.cMCStatus = cMCStatus;
        this.bodyList = new DERSequence(bodyList);
    }

    public CMCStatusInfoBuilder setStatusString(String statusString) {
        this.statusString = new DERUTF8String(statusString);
        return this;
    }

    public CMCStatusInfoBuilder setOtherInfo(CMCFailInfo failInfo) {
        this.otherInfo = new OtherInfo(failInfo);
        return this;
    }

    public CMCStatusInfoBuilder setOtherInfo(PendInfo pendInfo) {
        this.otherInfo = new OtherInfo(pendInfo);
        return this;
    }

    public CMCStatusInfo build() {
        return new CMCStatusInfo(this.cMCStatus, this.bodyList, this.statusString, this.otherInfo);
    }
}