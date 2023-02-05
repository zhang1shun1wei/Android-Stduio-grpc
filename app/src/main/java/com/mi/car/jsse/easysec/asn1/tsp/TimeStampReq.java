package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;

public class TimeStampReq extends ASN1Object {
    ASN1Integer version;
    MessageImprint messageImprint;
    ASN1ObjectIdentifier tsaPolicy;
    ASN1Integer nonce;
    ASN1Boolean certReq;
    Extensions extensions;

    public static TimeStampReq getInstance(Object o) {
        if (o instanceof TimeStampReq) {
            return (TimeStampReq)o;
        } else {
            return o != null ? new TimeStampReq(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private TimeStampReq(ASN1Sequence seq) {
        int nbObjects = seq.size();
        int seqStart = 0;
        this.version = ASN1Integer.getInstance(seq.getObjectAt(seqStart));
        seqStart = seqStart + 1;
        this.messageImprint = MessageImprint.getInstance(seq.getObjectAt(seqStart));
        ++seqStart;

        for(int opt = seqStart; opt < nbObjects; ++opt) {
            if (seq.getObjectAt(opt) instanceof ASN1ObjectIdentifier) {
                this.checkOption(this.tsaPolicy, opt, 2);
                this.tsaPolicy = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(opt));
            } else if (seq.getObjectAt(opt) instanceof ASN1Integer) {
                this.checkOption(this.nonce, opt, 3);
                this.nonce = ASN1Integer.getInstance(seq.getObjectAt(opt));
            } else if (seq.getObjectAt(opt) instanceof ASN1Boolean) {
                this.checkOption(this.certReq, opt, 4);
                this.certReq = ASN1Boolean.getInstance(seq.getObjectAt(opt));
            } else {
                if (!(seq.getObjectAt(opt) instanceof ASN1TaggedObject)) {
                    throw new IllegalArgumentException("unidentified structure in sequence");
                }

                this.checkOption(this.extensions, opt, 5);
                ASN1TaggedObject tagged = (ASN1TaggedObject)seq.getObjectAt(opt);
                if (tagged.getTagNo() == 0) {
                    this.extensions = Extensions.getInstance(tagged, false);
                }
            }
        }

    }

    private void checkOption(Object o, int index, int maxOption) {
        if (o != null || index > maxOption) {
            throw new IllegalArgumentException("badly placed optional in sequence");
        }
    }

    public TimeStampReq(MessageImprint messageImprint, ASN1ObjectIdentifier tsaPolicy, ASN1Integer nonce, ASN1Boolean certReq, Extensions extensions) {
        this.version = new ASN1Integer(1L);
        this.messageImprint = messageImprint;
        this.tsaPolicy = tsaPolicy;
        this.nonce = nonce;
        this.certReq = certReq;
        this.extensions = extensions;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public ASN1ObjectIdentifier getReqPolicy() {
        return this.tsaPolicy;
    }

    public ASN1Integer getNonce() {
        return this.nonce;
    }

    public ASN1Boolean getCertReq() {
        return this.certReq == null ? ASN1Boolean.FALSE : this.certReq;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        v.add(this.version);
        v.add(this.messageImprint);
        if (this.tsaPolicy != null) {
            v.add(this.tsaPolicy);
        }

        if (this.nonce != null) {
            v.add(this.nonce);
        }

        if (this.certReq != null && this.certReq.isTrue()) {
            v.add(this.certReq);
        }

        if (this.extensions != null) {
            v.add(new DERTaggedObject(false, 0, this.extensions));
        }

        return new DERSequence(v);
    }
}
