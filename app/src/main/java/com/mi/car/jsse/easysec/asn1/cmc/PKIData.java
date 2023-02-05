//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class PKIData extends ASN1Object {
    private final TaggedAttribute[] controlSequence;
    private final TaggedRequest[] reqSequence;
    private final TaggedContentInfo[] cmsSequence;
    private final OtherMsg[] otherMsgSequence;

    public PKIData(TaggedAttribute[] controlSequence, TaggedRequest[] reqSequence, TaggedContentInfo[] cmsSequence, OtherMsg[] otherMsgSequence) {
        this.controlSequence = this.copy(controlSequence);
        this.reqSequence = this.copy(reqSequence);
        this.cmsSequence = this.copy(cmsSequence);
        this.otherMsgSequence = this.copy(otherMsgSequence);
    }

    private PKIData(ASN1Sequence seq) {
        if (seq.size() != 4) {
            throw new IllegalArgumentException("Sequence not 4 elements.");
        } else {
            ASN1Sequence s = (ASN1Sequence)seq.getObjectAt(0);
            this.controlSequence = new TaggedAttribute[s.size()];

            int t;
            for(t = 0; t < this.controlSequence.length; ++t) {
                this.controlSequence[t] = TaggedAttribute.getInstance(s.getObjectAt(t));
            }

            s = (ASN1Sequence)seq.getObjectAt(1);
            this.reqSequence = new TaggedRequest[s.size()];

            for(t = 0; t < this.reqSequence.length; ++t) {
                this.reqSequence[t] = TaggedRequest.getInstance(s.getObjectAt(t));
            }

            s = (ASN1Sequence)seq.getObjectAt(2);
            this.cmsSequence = new TaggedContentInfo[s.size()];

            for(t = 0; t < this.cmsSequence.length; ++t) {
                this.cmsSequence[t] = TaggedContentInfo.getInstance(s.getObjectAt(t));
            }

            s = (ASN1Sequence)seq.getObjectAt(3);
            this.otherMsgSequence = new OtherMsg[s.size()];

            for(t = 0; t < this.otherMsgSequence.length; ++t) {
                this.otherMsgSequence[t] = OtherMsg.getInstance(s.getObjectAt(t));
            }

        }
    }

    public static PKIData getInstance(Object src) {
        if (src instanceof PKIData) {
            return (PKIData)src;
        } else {
            return src != null ? new PKIData(ASN1Sequence.getInstance(src)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        return new DERSequence(new ASN1Encodable[]{new DERSequence(this.controlSequence), new DERSequence(this.reqSequence), new DERSequence(this.cmsSequence), new DERSequence(this.otherMsgSequence)});
    }

    public TaggedAttribute[] getControlSequence() {
        return this.copy(this.controlSequence);
    }

    private TaggedAttribute[] copy(TaggedAttribute[] taggedAtts) {
        TaggedAttribute[] tmp = new TaggedAttribute[taggedAtts.length];
        System.arraycopy(taggedAtts, 0, tmp, 0, tmp.length);
        return tmp;
    }

    public TaggedRequest[] getReqSequence() {
        return this.copy(this.reqSequence);
    }

    private TaggedRequest[] copy(TaggedRequest[] taggedReqs) {
        TaggedRequest[] tmp = new TaggedRequest[taggedReqs.length];
        System.arraycopy(taggedReqs, 0, tmp, 0, tmp.length);
        return tmp;
    }

    public TaggedContentInfo[] getCmsSequence() {
        return this.copy(this.cmsSequence);
    }

    private TaggedContentInfo[] copy(TaggedContentInfo[] taggedConts) {
        TaggedContentInfo[] tmp = new TaggedContentInfo[taggedConts.length];
        System.arraycopy(taggedConts, 0, tmp, 0, tmp.length);
        return tmp;
    }

    public OtherMsg[] getOtherMsgSequence() {
        return this.copy(this.otherMsgSequence);
    }

    private OtherMsg[] copy(OtherMsg[] otherMsgs) {
        OtherMsg[] tmp = new OtherMsg[otherMsgs.length];
        System.arraycopy(otherMsgs, 0, tmp, 0, tmp.length);
        return tmp;
    }
}