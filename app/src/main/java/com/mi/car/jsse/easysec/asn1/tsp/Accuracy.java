package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;

public class Accuracy extends ASN1Object {
    ASN1Integer seconds;
    ASN1Integer millis;
    ASN1Integer micros;
    protected static final int MIN_MILLIS = 1;
    protected static final int MAX_MILLIS = 999;
    protected static final int MIN_MICROS = 1;
    protected static final int MAX_MICROS = 999;

    protected Accuracy() {
    }

    public Accuracy(ASN1Integer seconds, ASN1Integer millis, ASN1Integer micros) {
        int microsValue;
        if (null != millis) {
            microsValue = millis.intValueExact();
            if (microsValue < 1 || microsValue > 999) {
                throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
            }
        }

        if (null != micros) {
            microsValue = micros.intValueExact();
            if (microsValue < 1 || microsValue > 999) {
                throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
            }
        }

        this.seconds = seconds;
        this.millis = millis;
        this.micros = micros;
    }

    private Accuracy(ASN1Sequence seq) {
        this.seconds = null;
        this.millis = null;
        this.micros = null;

        for(int i = 0; i < seq.size(); ++i) {
            if (seq.getObjectAt(i) instanceof ASN1Integer) {
                this.seconds = (ASN1Integer)seq.getObjectAt(i);
            } else if (seq.getObjectAt(i) instanceof ASN1TaggedObject) {
                ASN1TaggedObject extra = (ASN1TaggedObject)seq.getObjectAt(i);
                switch(extra.getTagNo()) {
                    case 0:
                        this.millis = ASN1Integer.getInstance(extra, false);
                        int millisValue = this.millis.intValueExact();
                        if (millisValue < 1 || millisValue > 999) {
                            throw new IllegalArgumentException("Invalid millis field : not in (1..999)");
                        }
                        break;
                    case 1:
                        this.micros = ASN1Integer.getInstance(extra, false);
                        int microsValue = this.micros.intValueExact();
                        if (microsValue < 1 || microsValue > 999) {
                            throw new IllegalArgumentException("Invalid micros field : not in (1..999)");
                        }
                        break;
                    default:
                        throw new IllegalArgumentException("Invalid tag number");
                }
            }
        }

    }

    public static Accuracy getInstance(Object o) {
        if (o instanceof Accuracy) {
            return (Accuracy)o;
        } else {
            return o != null ? new Accuracy(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1Integer getSeconds() {
        return this.seconds;
    }

    public ASN1Integer getMillis() {
        return this.millis;
    }

    public ASN1Integer getMicros() {
        return this.micros;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (this.seconds != null) {
            v.add(this.seconds);
        }

        if (this.millis != null) {
            v.add(new DERTaggedObject(false, 0, this.millis));
        }

        if (this.micros != null) {
            v.add(new DERTaggedObject(false, 1, this.micros));
        }

        return new DERSequence(v);
    }
}
