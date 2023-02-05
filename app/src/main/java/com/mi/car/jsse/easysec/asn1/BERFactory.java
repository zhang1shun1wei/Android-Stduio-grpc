package com.mi.car.jsse.easysec.asn1;

/* access modifiers changed from: package-private */
public class BERFactory {
    static final BERSequence EMPTY_SEQUENCE = new BERSequence();
    static final BERSet EMPTY_SET = new BERSet();

    BERFactory() {
    }

    static BERSequence createSequence(ASN1EncodableVector v) {
        if (v.size() < 1) {
            return EMPTY_SEQUENCE;
        }
        return new BERSequence(v);
    }

    static BERSet createSet(ASN1EncodableVector v) {
        if (v.size() < 1) {
            return EMPTY_SET;
        }
        return new BERSet(v);
    }
}
