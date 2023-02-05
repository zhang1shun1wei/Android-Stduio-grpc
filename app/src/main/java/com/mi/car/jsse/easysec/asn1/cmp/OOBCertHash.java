//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmp;

import com.mi.car.jsse.easysec.asn1.ASN1BitString;
import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERBitString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.crmf.CertId;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;

public class OOBCertHash extends ASN1Object {
    private AlgorithmIdentifier hashAlg;
    private CertId certId;
    private final ASN1BitString hashVal;

    private OOBCertHash(ASN1Sequence seq) {
        int index = seq.size() - 1;
        this.hashVal = ASN1BitString.getInstance(seq.getObjectAt(index--));

        for(int i = index; i >= 0; --i) {
            ASN1TaggedObject tObj = (ASN1TaggedObject)seq.getObjectAt(i);
            if (tObj.getTagNo() == 0) {
                this.hashAlg = AlgorithmIdentifier.getInstance(tObj, true);
            } else {
                this.certId = CertId.getInstance(tObj, true);
            }
        }

    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, byte[] hashVal) {
        this(hashAlg, certId, new DERBitString(hashVal));
    }

    public OOBCertHash(AlgorithmIdentifier hashAlg, CertId certId, DERBitString hashVal) {
        this.hashAlg = hashAlg;
        this.certId = certId;
        this.hashVal = hashVal;
    }

    public static OOBCertHash getInstance(Object o) {
        if (o instanceof OOBCertHash) {
            return (OOBCertHash)o;
        } else {
            return o != null ? new OOBCertHash(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getHashAlg() {
        return this.hashAlg;
    }

    public CertId getCertId() {
        return this.certId;
    }

    public ASN1BitString getHashVal() {
        return this.hashVal;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        this.addOptional(v, 0, this.hashAlg);
        this.addOptional(v, 1, this.certId);
        v.add(this.hashVal);
        return new DERSequence(v);
    }

    private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj) {
        if (obj != null) {
            v.add(new DERTaggedObject(true, tagNo, obj));
        }

    }
}