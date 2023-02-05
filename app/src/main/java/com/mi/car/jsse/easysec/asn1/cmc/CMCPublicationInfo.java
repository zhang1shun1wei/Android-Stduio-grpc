//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.crmf.PKIPublicationInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class CMCPublicationInfo extends ASN1Object {
    private final AlgorithmIdentifier hashAlg;
    private final ASN1Sequence certHashes;
    private final PKIPublicationInfo pubInfo;

    public CMCPublicationInfo(AlgorithmIdentifier hashAlg, byte[][] anchorHashes, PKIPublicationInfo pubInfo) {
        this.hashAlg = hashAlg;
        ASN1EncodableVector v = new ASN1EncodableVector(anchorHashes.length);

        for(int i = 0; i != anchorHashes.length; ++i) {
            v.add(new DEROctetString(Arrays.clone(anchorHashes[i])));
        }

        this.certHashes = new DERSequence(v);
        this.pubInfo = pubInfo;
    }

    private CMCPublicationInfo(ASN1Sequence seq) {
        if (seq.size() != 3) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
            this.certHashes = ASN1Sequence.getInstance(seq.getObjectAt(1));
            this.pubInfo = PKIPublicationInfo.getInstance(seq.getObjectAt(2));
        }
    }

    public static CMCPublicationInfo getInstance(Object o) {
        if (o instanceof CMCPublicationInfo) {
            return (CMCPublicationInfo)o;
        } else {
            return o != null ? new CMCPublicationInfo(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getHashAlg() {
        return this.hashAlg;
    }

    public byte[][] getCertHashes() {
        byte[][] hashes = new byte[this.certHashes.size()][];

        for(int i = 0; i != hashes.length; ++i) {
            hashes[i] = Arrays.clone(ASN1OctetString.getInstance(this.certHashes.getObjectAt(i)).getOctets());
        }

        return hashes;
    }

    public PKIPublicationInfo getPubInfo() {
        return this.pubInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.hashAlg);
        v.add(this.certHashes);
        v.add(this.pubInfo);
        return new DERSequence(v);
    }
}