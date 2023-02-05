package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class XMSSMTKeyParams extends ASN1Object {
    private final int height;
    private final int layers;
    private final AlgorithmIdentifier treeDigest;
    private final ASN1Integer version;

    public XMSSMTKeyParams(int height2, int layers2, AlgorithmIdentifier treeDigest2) {
        this.version = new ASN1Integer(0);
        this.height = height2;
        this.layers = layers2;
        this.treeDigest = treeDigest2;
    }

    private XMSSMTKeyParams(ASN1Sequence sequence) {
        this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
        this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).intValueExact();
        this.layers = ASN1Integer.getInstance(sequence.getObjectAt(2)).intValueExact();
        this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
    }

    public static XMSSMTKeyParams getInstance(Object o) {
        if (o instanceof XMSSMTKeyParams) {
            return (XMSSMTKeyParams) o;
        }
        if (o != null) {
            return new XMSSMTKeyParams(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public int getHeight() {
        return this.height;
    }

    public int getLayers() {
        return this.layers;
    }

    public AlgorithmIdentifier getTreeDigest() {
        return this.treeDigest;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(this.version);
        v.add(new ASN1Integer((long) this.height));
        v.add(new ASN1Integer((long) this.layers));
        v.add(this.treeDigest);
        return new DERSequence(v);
    }
}
