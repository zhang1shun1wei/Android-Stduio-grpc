//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class PBMParameter extends ASN1Object {
    private final ASN1OctetString salt;
    private final AlgorithmIdentifier owf;
    private final ASN1Integer iterationCount;
    private final AlgorithmIdentifier mac;

    private PBMParameter(ASN1Sequence seq) {
        this.salt = ASN1OctetString.getInstance(seq.getObjectAt(0));
        this.owf = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.iterationCount = ASN1Integer.getInstance(seq.getObjectAt(2));
        this.mac = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
    }

    public PBMParameter(byte[] salt, AlgorithmIdentifier owf, int iterationCount, AlgorithmIdentifier mac) {
        this(new DEROctetString(salt), owf, new ASN1Integer((long)iterationCount), mac);
    }

    public PBMParameter(ASN1OctetString salt, AlgorithmIdentifier owf, ASN1Integer iterationCount, AlgorithmIdentifier mac) {
        this.salt = salt;
        this.owf = owf;
        this.iterationCount = iterationCount;
        this.mac = mac;
    }

    public static PBMParameter getInstance(Object o) {
        if (o instanceof PBMParameter) {
            return (PBMParameter)o;
        } else {
            return o != null ? new PBMParameter(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1OctetString getSalt() {
        return this.salt;
    }

    public AlgorithmIdentifier getOwf() {
        return this.owf;
    }

    public ASN1Integer getIterationCount() {
        return this.iterationCount;
    }

    public AlgorithmIdentifier getMac() {
        return this.mac;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        v.add(this.salt);
        v.add(this.owf);
        v.add(this.iterationCount);
        v.add(this.mac);
        return new DERSequence(v);
    }
}
