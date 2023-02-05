package com.mi.car.jsse.easysec.asn1.nist;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class KMACwithSHAKE256_params extends ASN1Object {
    private static final int DEF_LENGTH = 512;
    private static final byte[] EMPTY_STRING = new byte[0];
    private final byte[] customizationString;
    private final int outputLength;

    public KMACwithSHAKE256_params(int outputLength2) {
        this.outputLength = outputLength2;
        this.customizationString = EMPTY_STRING;
    }

    public KMACwithSHAKE256_params(int outputLength2, byte[] customizationString2) {
        this.outputLength = outputLength2;
        this.customizationString = Arrays.clone(customizationString2);
    }

    public static KMACwithSHAKE256_params getInstance(Object o) {
        if (o instanceof KMACwithSHAKE256_params) {
            return (KMACwithSHAKE256_params) o;
        }
        if (o != null) {
            return new KMACwithSHAKE256_params(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private KMACwithSHAKE256_params(ASN1Sequence seq) {
        if (seq.size() > 2) {
            throw new IllegalArgumentException("sequence size greater than 2");
        } else if (seq.size() == 2) {
            this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
            this.customizationString = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
        } else if (seq.size() != 1) {
            this.outputLength = 512;
            this.customizationString = EMPTY_STRING;
        } else if (seq.getObjectAt(0) instanceof ASN1Integer) {
            this.outputLength = ASN1Integer.getInstance(seq.getObjectAt(0)).intValueExact();
            this.customizationString = EMPTY_STRING;
        } else {
            this.outputLength = 512;
            this.customizationString = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
        }
    }

    public int getOutputLength() {
        return this.outputLength;
    }

    public byte[] getCustomizationString() {
        return Arrays.clone(this.customizationString);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.outputLength != 512) {
            v.add(new ASN1Integer((long) this.outputLength));
        }
        if (this.customizationString.length != 0) {
            v.add(new DEROctetString(getCustomizationString()));
        }
        return new DERSequence(v);
    }
}
