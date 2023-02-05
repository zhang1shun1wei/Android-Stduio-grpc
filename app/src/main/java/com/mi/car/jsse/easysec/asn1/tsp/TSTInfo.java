package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Boolean;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import java.util.Enumeration;

public class TSTInfo extends ASN1Object {
    private Accuracy accuracy;
    private Extensions extensions;
    private ASN1GeneralizedTime genTime;
    private MessageImprint messageImprint;
    private ASN1Integer nonce;
    private ASN1Boolean ordering;
    private ASN1Integer serialNumber;
    private GeneralName tsa;
    private ASN1ObjectIdentifier tsaPolicyId;
    private ASN1Integer version;

    public static TSTInfo getInstance(Object o) {
        if (o instanceof TSTInfo) {
            return (TSTInfo) o;
        }
        if (o != null) {
            return new TSTInfo(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private TSTInfo(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.version = ASN1Integer.getInstance(e.nextElement());
        this.tsaPolicyId = ASN1ObjectIdentifier.getInstance(e.nextElement());
        this.messageImprint = MessageImprint.getInstance(e.nextElement());
        this.serialNumber = ASN1Integer.getInstance(e.nextElement());
        this.genTime = ASN1GeneralizedTime.getInstance(e.nextElement());
        this.ordering = ASN1Boolean.getInstance(false);
        while (e.hasMoreElements()) {
            ASN1Object o = (ASN1Object) e.nextElement();
            if (o instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) o;
                switch (tagged.getTagNo()) {
                    case 0:
                        this.tsa = GeneralName.getInstance(tagged, true);
                        continue;
                    case 1:
                        this.extensions = Extensions.getInstance(tagged, false);
                        continue;
                    default:
                        throw new IllegalArgumentException("Unknown tag value " + tagged.getTagNo());
                }
            } else if ((o instanceof ASN1Sequence) || (o instanceof Accuracy)) {
                this.accuracy = Accuracy.getInstance(o);
            } else if (o instanceof ASN1Boolean) {
                this.ordering = ASN1Boolean.getInstance(o);
            } else if (o instanceof ASN1Integer) {
                this.nonce = ASN1Integer.getInstance(o);
            }
        }
    }

    public TSTInfo(ASN1ObjectIdentifier tsaPolicyId2, MessageImprint messageImprint2, ASN1Integer serialNumber2, ASN1GeneralizedTime genTime2, Accuracy accuracy2, ASN1Boolean ordering2, ASN1Integer nonce2, GeneralName tsa2, Extensions extensions2) {
        this.version = new ASN1Integer(1);
        this.tsaPolicyId = tsaPolicyId2;
        this.messageImprint = messageImprint2;
        this.serialNumber = serialNumber2;
        this.genTime = genTime2;
        this.accuracy = accuracy2;
        this.ordering = ordering2;
        this.nonce = nonce2;
        this.tsa = tsa2;
        this.extensions = extensions2;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public MessageImprint getMessageImprint() {
        return this.messageImprint;
    }

    public ASN1ObjectIdentifier getPolicy() {
        return this.tsaPolicyId;
    }

    public ASN1Integer getSerialNumber() {
        return this.serialNumber;
    }

    public Accuracy getAccuracy() {
        return this.accuracy;
    }

    public ASN1GeneralizedTime getGenTime() {
        return this.genTime;
    }

    public ASN1Boolean getOrdering() {
        return this.ordering;
    }

    public ASN1Integer getNonce() {
        return this.nonce;
    }

    public GeneralName getTsa() {
        return this.tsa;
    }

    public Extensions getExtensions() {
        return this.extensions;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(10);
        seq.add(this.version);
        seq.add(this.tsaPolicyId);
        seq.add(this.messageImprint);
        seq.add(this.serialNumber);
        seq.add(this.genTime);
        if (this.accuracy != null) {
            seq.add(this.accuracy);
        }
        if (this.ordering != null && this.ordering.isTrue()) {
            seq.add(this.ordering);
        }
        if (this.nonce != null) {
            seq.add(this.nonce);
        }
        if (this.tsa != null) {
            seq.add(new DERTaggedObject(true, 0, this.tsa));
        }
        if (this.extensions != null) {
            seq.add(new DERTaggedObject(false, 1, this.extensions));
        }
        return new DERSequence(seq);
    }
}
