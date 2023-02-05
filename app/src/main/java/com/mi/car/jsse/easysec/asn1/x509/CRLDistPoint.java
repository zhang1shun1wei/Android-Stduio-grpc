package com.mi.car.jsse.easysec.asn1.x509;

import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.util.Strings;

public class CRLDistPoint extends ASN1Object {
    ASN1Sequence seq = null;

    public static CRLDistPoint getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static CRLDistPoint getInstance(Object obj) {
        if (obj instanceof CRLDistPoint) {
            return (CRLDistPoint) obj;
        }
        if (obj != null) {
            return new CRLDistPoint(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static CRLDistPoint fromExtensions(Extensions extensions) {
        return getInstance(Extensions.getExtensionParsedValue(extensions, Extension.cRLDistributionPoints));
    }

    private CRLDistPoint(ASN1Sequence seq2) {
        this.seq = seq2;
    }

    public CRLDistPoint(DistributionPoint[] points) {
        this.seq = new DERSequence(points);
    }

    public DistributionPoint[] getDistributionPoints() {
        DistributionPoint[] dp = new DistributionPoint[this.seq.size()];
        for (int i = 0; i != this.seq.size(); i++) {
            dp[i] = DistributionPoint.getInstance(this.seq.getObjectAt(i));
        }
        return dp;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.seq;
    }

    public String toString() {
        StringBuffer buf = new StringBuffer();
        String sep = Strings.lineSeparator();
        buf.append("CRLDistPoint:");
        buf.append(sep);
        DistributionPoint[] dp = getDistributionPoints();
        for (int i = 0; i != dp.length; i++) {
            buf.append("    ");
            buf.append(dp[i]);
            buf.append(sep);
        }
        return buf.toString();
    }
}
