package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;

public class ParSet extends ASN1Object {
    private int[] h;
    private int[] k;
    private int t;
    private int[] w;

    private static int checkBigIntegerInIntRangeAndPositive(ASN1Encodable e) {
        int value = ((ASN1Integer) e).intValueExact();
        if (value > 0) {
            return value;
        }
        throw new IllegalArgumentException("BigInteger not in Range: " + value);
    }

    private ParSet(ASN1Sequence seq) {
        if (seq.size() != 4) {
            throw new IllegalArgumentException("sie of seqOfParams = " + seq.size());
        }
        this.t = checkBigIntegerInIntRangeAndPositive(seq.getObjectAt(0));
        ASN1Sequence seqOfPSh = (ASN1Sequence) seq.getObjectAt(1);
        ASN1Sequence seqOfPSw = (ASN1Sequence) seq.getObjectAt(2);
        ASN1Sequence seqOfPSK = (ASN1Sequence) seq.getObjectAt(3);
        if (seqOfPSh.size() == this.t && seqOfPSw.size() == this.t && seqOfPSK.size() == this.t) {
            this.h = new int[seqOfPSh.size()];
            this.w = new int[seqOfPSw.size()];
            this.k = new int[seqOfPSK.size()];
            for (int i = 0; i < this.t; i++) {
                this.h[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSh.getObjectAt(i));
                this.w[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSw.getObjectAt(i));
                this.k[i] = checkBigIntegerInIntRangeAndPositive(seqOfPSK.getObjectAt(i));
            }
            return;
        }
        throw new IllegalArgumentException("invalid size of sequences");
    }

    public ParSet(int t2, int[] h2, int[] w2, int[] k2) {
        this.t = t2;
        this.h = h2;
        this.w = w2;
        this.k = k2;
    }

    public static ParSet getInstance(Object o) {
        if (o instanceof ParSet) {
            return (ParSet) o;
        }
        if (o != null) {
            return new ParSet(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getT() {
        return this.t;
    }

    public int[] getH() {
        return Arrays.clone(this.h);
    }

    public int[] getW() {
        return Arrays.clone(this.w);
    }

    public int[] getK() {
        return Arrays.clone(this.k);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seqOfPSh = new ASN1EncodableVector();
        ASN1EncodableVector seqOfPSw = new ASN1EncodableVector();
        ASN1EncodableVector seqOfPSK = new ASN1EncodableVector();
        for (int i = 0; i < this.h.length; i++) {
            seqOfPSh.add(new ASN1Integer((long) this.h[i]));
            seqOfPSw.add(new ASN1Integer((long) this.w[i]));
            seqOfPSK.add(new ASN1Integer((long) this.k[i]));
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer((long) this.t));
        v.add(new DERSequence(seqOfPSh));
        v.add(new DERSequence(seqOfPSw));
        v.add(new DERSequence(seqOfPSK));
        return new DERSequence(v);
    }
}
