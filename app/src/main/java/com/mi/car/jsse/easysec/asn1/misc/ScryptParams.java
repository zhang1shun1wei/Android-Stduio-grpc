package com.mi.car.jsse.easysec.asn1.misc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class ScryptParams extends ASN1Object {
    private final BigInteger blockSize;
    private final BigInteger costParameter;
    private final BigInteger keyLength;
    private final BigInteger parallelizationParameter;
    private final byte[] salt;

    public ScryptParams(byte[] salt2, int costParameter2, int blockSize2, int parallelizationParameter2) {
        this(salt2, BigInteger.valueOf((long) costParameter2), BigInteger.valueOf((long) blockSize2), BigInteger.valueOf((long) parallelizationParameter2), (BigInteger) null);
    }

    public ScryptParams(byte[] salt2, int costParameter2, int blockSize2, int parallelizationParameter2, int keyLength2) {
        this(salt2, BigInteger.valueOf((long) costParameter2), BigInteger.valueOf((long) blockSize2), BigInteger.valueOf((long) parallelizationParameter2), BigInteger.valueOf((long) keyLength2));
    }

    public ScryptParams(byte[] salt2, BigInteger costParameter2, BigInteger blockSize2, BigInteger parallelizationParameter2, BigInteger keyLength2) {
        this.salt = Arrays.clone(salt2);
        this.costParameter = costParameter2;
        this.blockSize = blockSize2;
        this.parallelizationParameter = parallelizationParameter2;
        this.keyLength = keyLength2;
    }

    public static ScryptParams getInstance(Object o) {
        if (o instanceof ScryptParams) {
            return (ScryptParams) o;
        }
        if (o != null) {
            return new ScryptParams(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private ScryptParams(ASN1Sequence seq) {
        if (seq.size() == 4 || seq.size() == 5) {
            this.salt = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets());
            this.costParameter = ASN1Integer.getInstance(seq.getObjectAt(1)).getValue();
            this.blockSize = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
            this.parallelizationParameter = ASN1Integer.getInstance(seq.getObjectAt(3)).getValue();
            if (seq.size() == 5) {
                this.keyLength = ASN1Integer.getInstance(seq.getObjectAt(4)).getValue();
            } else {
                this.keyLength = null;
            }
        } else {
            throw new IllegalArgumentException("invalid sequence: size = " + seq.size());
        }
    }

    public byte[] getSalt() {
        return Arrays.clone(this.salt);
    }

    public BigInteger getCostParameter() {
        return this.costParameter;
    }

    public BigInteger getBlockSize() {
        return this.blockSize;
    }

    public BigInteger getParallelizationParameter() {
        return this.parallelizationParameter;
    }

    public BigInteger getKeyLength() {
        return this.keyLength;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(new DEROctetString(this.salt));
        v.add(new ASN1Integer(this.costParameter));
        v.add(new ASN1Integer(this.blockSize));
        v.add(new ASN1Integer(this.parallelizationParameter));
        if (this.keyLength != null) {
            v.add(new ASN1Integer(this.keyLength));
        }
        return new DERSequence(v);
    }
}
