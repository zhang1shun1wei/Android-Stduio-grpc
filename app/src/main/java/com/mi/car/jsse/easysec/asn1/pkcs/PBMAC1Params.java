package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

public class PBMAC1Params extends ASN1Object implements PKCSObjectIdentifiers {
    private AlgorithmIdentifier func;
    private AlgorithmIdentifier scheme;

    public static PBMAC1Params getInstance(Object obj) {
        if (obj instanceof PBMAC1Params) {
            return (PBMAC1Params) obj;
        }
        if (obj != null) {
            return new PBMAC1Params(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public PBMAC1Params(AlgorithmIdentifier keyDevFunc, AlgorithmIdentifier encScheme) {
        this.func = keyDevFunc;
        this.scheme = encScheme;
    }

    private PBMAC1Params(ASN1Sequence obj) {
        Enumeration e = obj.getObjects();
        ASN1Sequence funcSeq = ASN1Sequence.getInstance(((ASN1Encodable) e.nextElement()).toASN1Primitive());
        if (funcSeq.getObjectAt(0).equals(id_PBKDF2)) {
            this.func = new AlgorithmIdentifier(id_PBKDF2, PBKDF2Params.getInstance(funcSeq.getObjectAt(1)));
        } else {
            this.func = AlgorithmIdentifier.getInstance(funcSeq);
        }
        this.scheme = AlgorithmIdentifier.getInstance(e.nextElement());
    }

    public AlgorithmIdentifier getKeyDerivationFunc() {
        return this.func;
    }

    public AlgorithmIdentifier getMessageAuthScheme() {
        return this.scheme;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.func);
        v.add(this.scheme);
        return new DERSequence(v);
    }
}
