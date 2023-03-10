package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class MacData extends ASN1Object {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    DigestInfo digInfo;
    BigInteger iterationCount;
    byte[] salt;

    public static MacData getInstance(Object obj) {
        if (obj instanceof MacData) {
            return (MacData) obj;
        }
        if (obj != null) {
            return new MacData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private MacData(ASN1Sequence seq) {
        this.digInfo = DigestInfo.getInstance(seq.getObjectAt(0));
        this.salt = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(1)).getOctets());
        if (seq.size() == 3) {
            this.iterationCount = ASN1Integer.getInstance(seq.getObjectAt(2)).getValue();
        } else {
            this.iterationCount = ONE;
        }
    }

    public MacData(DigestInfo digInfo2, byte[] salt2, int iterationCount2) {
        this.digInfo = digInfo2;
        this.salt = Arrays.clone(salt2);
        this.iterationCount = BigInteger.valueOf((long) iterationCount2);
    }

    public DigestInfo getMac() {
        return this.digInfo;
    }

    public byte[] getSalt() {
        return Arrays.clone(this.salt);
    }

    public BigInteger getIterationCount() {
        return this.iterationCount;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.digInfo);
        v.add(new DEROctetString(this.salt));
        if (!this.iterationCount.equals(ONE)) {
            v.add(new ASN1Integer(this.iterationCount));
        }
        return new DERSequence(v);
    }
}
