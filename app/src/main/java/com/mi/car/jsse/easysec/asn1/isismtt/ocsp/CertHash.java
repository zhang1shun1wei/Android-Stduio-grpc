package com.mi.car.jsse.easysec.asn1.isismtt.ocsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class CertHash extends ASN1Object {
    private byte[] certificateHash;
    private AlgorithmIdentifier hashAlgorithm;

    public static CertHash getInstance(Object obj) {
        if (obj == null || (obj instanceof CertHash)) {
            return (CertHash) obj;
        }
        if (obj instanceof ASN1Sequence) {
            return new CertHash((ASN1Sequence) obj);
        }
        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    private CertHash(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.certificateHash = DEROctetString.getInstance(seq.getObjectAt(1)).getOctets();
    }

    public CertHash(AlgorithmIdentifier hashAlgorithm2, byte[] certificateHash2) {
        this.hashAlgorithm = hashAlgorithm2;
        this.certificateHash = new byte[certificateHash2.length];
        System.arraycopy(certificateHash2, 0, this.certificateHash, 0, certificateHash2.length);
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[] getCertificateHash() {
        return Arrays.clone(this.certificateHash);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vec = new ASN1EncodableVector(2);
        vec.add(this.hashAlgorithm);
        vec.add(new DEROctetString(this.certificateHash));
        return new DERSequence(vec);
    }
}
