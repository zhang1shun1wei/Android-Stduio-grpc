package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class SPHINCS256KeyParams extends ASN1Object {
    private final AlgorithmIdentifier treeDigest;
    private final ASN1Integer version;

    public SPHINCS256KeyParams(AlgorithmIdentifier treeDigest2) {
        this.version = new ASN1Integer(0);
        this.treeDigest = treeDigest2;
    }

    private SPHINCS256KeyParams(ASN1Sequence sequence) {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(1));
    }

    public static final SPHINCS256KeyParams getInstance(Object o) {
        if (o instanceof SPHINCS256KeyParams) {
            return (SPHINCS256KeyParams) o;
        }
        if (o != null) {
            return new SPHINCS256KeyParams(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public AlgorithmIdentifier getTreeDigest() {
        return this.treeDigest;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(this.treeDigest);
        return new DERSequence(v);
    }
}
