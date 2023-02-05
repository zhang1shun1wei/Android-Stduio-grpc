package com.mi.car.jsse.easysec.asn1.mozilla;

import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import com.mi.car.jsse.easysec.asn1.x509.SubjectPublicKeyInfo;

public class PublicKeyAndChallenge extends ASN1Object {
    private ASN1IA5String challenge;
    private ASN1Sequence pkacSeq;
    private SubjectPublicKeyInfo spki;

    public static PublicKeyAndChallenge getInstance(Object obj) {
        if (obj instanceof PublicKeyAndChallenge) {
            return (PublicKeyAndChallenge) obj;
        }
        if (obj != null) {
            return new PublicKeyAndChallenge(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private PublicKeyAndChallenge(ASN1Sequence seq) {
        this.pkacSeq = seq;
        this.spki = SubjectPublicKeyInfo.getInstance(seq.getObjectAt(0));
        this.challenge = ASN1IA5String.getInstance(seq.getObjectAt(1));
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        return this.pkacSeq;
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo() {
        return this.spki;
    }

    public DERIA5String getChallenge() {
        if (this.challenge == null || (this.challenge instanceof DERIA5String)) {
            return (DERIA5String) this.challenge;
        }
        return new DERIA5String(this.challenge.getString(), false);
    }

    public ASN1IA5String getChallengeIA5() {
        return this.challenge;
    }
}
