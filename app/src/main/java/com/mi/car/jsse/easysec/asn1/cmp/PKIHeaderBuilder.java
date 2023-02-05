//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.util.Arrays;

public class PKIHeaderBuilder {
    private final ASN1Integer pvno;
    private final GeneralName sender;
    private final GeneralName recipient;
    private ASN1GeneralizedTime messageTime;
    private AlgorithmIdentifier protectionAlg;
    private ASN1OctetString senderKID;
    private ASN1OctetString recipKID;
    private ASN1OctetString transactionID;
    private ASN1OctetString senderNonce;
    private ASN1OctetString recipNonce;
    private PKIFreeText freeText;
    private ASN1Sequence generalInfo;

    public PKIHeaderBuilder(int pvno, GeneralName sender, GeneralName recipient) {
        this(new ASN1Integer((long)pvno), sender, recipient);
    }

    private PKIHeaderBuilder(ASN1Integer pvno, GeneralName sender, GeneralName recipient) {
        this.pvno = pvno;
        this.sender = sender;
        this.recipient = recipient;
    }

    private static ASN1Sequence makeGeneralInfoSeq(InfoTypeAndValue generalInfo) {
        return new DERSequence(generalInfo);
    }

    private static ASN1Sequence makeGeneralInfoSeq(InfoTypeAndValue[] generalInfos) {
        ASN1Sequence genInfoSeq = null;
        if (generalInfos != null) {
            genInfoSeq = new DERSequence(generalInfos);
        }

        return genInfoSeq;
    }

    public PKIHeaderBuilder setMessageTime(ASN1GeneralizedTime time) {
        this.messageTime = time;
        return this;
    }

    public PKIHeaderBuilder setProtectionAlg(AlgorithmIdentifier aid) {
        this.protectionAlg = aid;
        return this;
    }

    public PKIHeaderBuilder setSenderKID(byte[] kid) {
        return this.setSenderKID((ASN1OctetString)(kid == null ? null : this.createClonedOctetString(kid)));
    }

    public PKIHeaderBuilder setSenderKID(ASN1OctetString kid) {
        this.senderKID = kid;
        return this;
    }

    public PKIHeaderBuilder setRecipKID(byte[] kid) {
        return this.setRecipKID((ASN1OctetString)(kid == null ? null : this.createClonedOctetString(kid)));
    }

    public PKIHeaderBuilder setRecipKID(ASN1OctetString kid) {
        this.recipKID = kid;
        return this;
    }

    public PKIHeaderBuilder setTransactionID(byte[] tid) {
        return this.setTransactionID((ASN1OctetString)(tid == null ? null : this.createClonedOctetString(tid)));
    }

    public PKIHeaderBuilder setTransactionID(ASN1OctetString tid) {
        this.transactionID = tid;
        return this;
    }

    public PKIHeaderBuilder setSenderNonce(byte[] nonce) {
        return this.setSenderNonce((ASN1OctetString)(nonce == null ? null : this.createClonedOctetString(nonce)));
    }

    public PKIHeaderBuilder setSenderNonce(ASN1OctetString nonce) {
        this.senderNonce = nonce;
        return this;
    }

    public PKIHeaderBuilder setRecipNonce(byte[] nonce) {
        return this.setRecipNonce((ASN1OctetString)(nonce == null ? null : this.createClonedOctetString(nonce)));
    }

    public PKIHeaderBuilder setRecipNonce(ASN1OctetString nonce) {
        this.recipNonce = nonce;
        return this;
    }

    public PKIHeaderBuilder setFreeText(PKIFreeText text) {
        this.freeText = text;
        return this;
    }

    public PKIHeaderBuilder setGeneralInfo(InfoTypeAndValue genInfo) {
        return this.setGeneralInfo(makeGeneralInfoSeq(genInfo));
    }

    public PKIHeaderBuilder setGeneralInfo(InfoTypeAndValue[] genInfos) {
        return this.setGeneralInfo(makeGeneralInfoSeq(genInfos));
    }

    public PKIHeaderBuilder setGeneralInfo(ASN1Sequence seqOfInfoTypeAndValue) {
        this.generalInfo = seqOfInfoTypeAndValue;
        return this;
    }

    public PKIHeader build() {
        ASN1EncodableVector v = new ASN1EncodableVector(12);
        v.add(this.pvno);
        v.add(this.sender);
        v.add(this.recipient);
        this.addOptional(v, 0, this.messageTime);
        this.addOptional(v, 1, this.protectionAlg);
        this.addOptional(v, 2, this.senderKID);
        this.addOptional(v, 3, this.recipKID);
        this.addOptional(v, 4, this.transactionID);
        this.addOptional(v, 5, this.senderNonce);
        this.addOptional(v, 6, this.recipNonce);
        this.addOptional(v, 7, this.freeText);
        this.addOptional(v, 8, this.generalInfo);
        this.messageTime = null;
        this.protectionAlg = null;
        this.senderKID = null;
        this.recipKID = null;
        this.transactionID = null;
        this.senderNonce = null;
        this.recipNonce = null;
        this.freeText = null;
        this.generalInfo = null;
        return PKIHeader.getInstance(new DERSequence(v));
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }

    private DEROctetString createClonedOctetString(byte[] value) {
        return new DEROctetString(Arrays.clone(value));
    }
}
