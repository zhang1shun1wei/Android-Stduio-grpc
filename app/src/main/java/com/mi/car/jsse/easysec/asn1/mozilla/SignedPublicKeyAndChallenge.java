package com.mi.car.jsse.easysec.asn1.mozilla;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class SignedPublicKeyAndChallenge extends ASN1Object {
    private final ASN1Sequence pkacSeq;
    private final PublicKeyAndChallenge pubKeyAndChal;

    public static SignedPublicKeyAndChallenge getInstance(Object obj) {
        if (obj instanceof SignedPublicKeyAndChallenge) {
            return (SignedPublicKeyAndChallenge) obj;
        }
        if (obj != null) {
            return new SignedPublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private SignedPublicKeyAndChallenge(ASN1Sequence seq) {
        this.pkacSeq = seq;
        this.pubKeyAndChal = PublicKeyAndChallenge.getInstance(seq.getObjectAt(0));
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.pkacSeq;
    }

    public PublicKeyAndChallenge getPublicKeyAndChallenge() {
        return this.pubKeyAndChal;
    }

    public AlgorithmIdentifier getSignatureAlgorithm() {
        return AlgorithmIdentifier.getInstance(this.pkacSeq.getObjectAt(1));
    }

    public ASN1BitString getSignature() {
        return ASN1BitString.getInstance(this.pkacSeq.getObjectAt(2));
    }
}
