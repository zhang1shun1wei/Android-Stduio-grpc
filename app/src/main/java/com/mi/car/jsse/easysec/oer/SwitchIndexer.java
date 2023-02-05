package com.mi.car.jsse.easysec.oer;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;

public abstract class SwitchIndexer {
    public abstract ASN1Encodable get(int i);

    public static class Asn1SequenceIndexer extends SwitchIndexer {
        private final ASN1Sequence sequence;

        public Asn1SequenceIndexer(ASN1Sequence sequence2) {
            this.sequence = sequence2;
        }

        @Override // com.mi.car.jsse.easysec.oer.SwitchIndexer
        public ASN1Encodable get(int index) {
            return this.sequence.getObjectAt(index);
        }
    }

    public static class Asn1EncodableVectorIndexer extends SwitchIndexer {
        private final ASN1EncodableVector asn1EncodableVector;

        public Asn1EncodableVectorIndexer(ASN1EncodableVector asn1EncodableVector2) {
            this.asn1EncodableVector = asn1EncodableVector2;
        }

        @Override // com.mi.car.jsse.easysec.oer.SwitchIndexer
        public ASN1Encodable get(int index) {
            return this.asn1EncodableVector.get(index);
        }
    }

    public static class FixedValueIndexer extends SwitchIndexer {
        private final ASN1Encodable returnValue;

        public FixedValueIndexer(ASN1Encodable returnValue2) {
            this.returnValue = returnValue2;
        }

        @Override // com.mi.car.jsse.easysec.oer.SwitchIndexer
        public ASN1Encodable get(int index) {
            return this.returnValue;
        }
    }
}
