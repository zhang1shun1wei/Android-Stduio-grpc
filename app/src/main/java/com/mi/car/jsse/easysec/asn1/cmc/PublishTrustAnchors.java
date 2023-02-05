//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;
import java.math.BigInteger;

public class PublishTrustAnchors extends ASN1Object {
    private final ASN1Integer seqNumber;
    private final AlgorithmIdentifier hashAlgorithm;
    private final ASN1Sequence anchorHashes;

    public PublishTrustAnchors(BigInteger seqNumber, AlgorithmIdentifier hashAlgorithm, byte[][] anchorHashes) {
        this.seqNumber = new ASN1Integer(seqNumber);
        this.hashAlgorithm = hashAlgorithm;
        ASN1EncodableVector v = new ASN1EncodableVector(anchorHashes.length);

        for(int i = 0; i != anchorHashes.length; ++i) {
            v.add(new DEROctetString(Arrays.clone(anchorHashes[i])));
        }

        this.anchorHashes = new DERSequence(v);
    }

    private PublishTrustAnchors(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.seqNumber = ASN1Integer.getInstance(seq.getObjectAt(0));
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
            this.anchorHashes = ASN1Sequence.getInstance(seq.getObjectAt(2));
        }
    }

    public static PublishTrustAnchors getInstance(Object o) {
        if (o instanceof PublishTrustAnchors) {
            return (PublishTrustAnchors)o;
        } else {
            return o != null ? new PublishTrustAnchors(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public BigInteger getSeqNumber() {
        return this.seqNumber.getValue();
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[][] getAnchorHashes() {
        byte[][] hashes = new byte[this.anchorHashes.size()][];

        for(int i = 0; i != hashes.length; ++i) {
            hashes[i] = Arrays.clone(ASN1OctetString.getInstance(this.anchorHashes.getObjectAt(i)).getOctets());
        }

        return hashes;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.seqNumber);
        v.add(this.hashAlgorithm);
        v.add(this.anchorHashes);
        return new DERSequence(v);
    }
}