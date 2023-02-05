package com.mi.car.jsse.easysec.asn1;

/* access modifiers changed from: package-private */
public class DLFactory {
    static final DLSequence EMPTY_SEQUENCE = new DLSequence();
    static final DLSet EMPTY_SET = new DLSet();

    DLFactory() {
    }

    static DLSequence createSequence(ASN1EncodableVector v) {
        if (v.size() < 1) {
            return EMPTY_SEQUENCE;
        }
        return new DLSequence(v);
    }

    static DLSet createSet(ASN1EncodableVector v) {
        if (v.size() < 1) {
            return EMPTY_SET;
        }
        return new DLSet(v);
    }
}
