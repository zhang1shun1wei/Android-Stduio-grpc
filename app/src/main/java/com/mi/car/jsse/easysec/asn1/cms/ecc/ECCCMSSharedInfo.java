//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cms.ecc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class ECCCMSSharedInfo extends ASN1Object {
    private final AlgorithmIdentifier keyInfo;
    private final byte[] entityUInfo;
    private final byte[] suppPubInfo;

    public ECCCMSSharedInfo(AlgorithmIdentifier keyInfo, byte[] entityUInfo, byte[] suppPubInfo) {
        this.keyInfo = keyInfo;
        this.entityUInfo = Arrays.clone(entityUInfo);
        this.suppPubInfo = Arrays.clone(suppPubInfo);
    }

    public ECCCMSSharedInfo(AlgorithmIdentifier keyInfo, byte[] suppPubInfo) {
        this.keyInfo = keyInfo;
        this.entityUInfo = null;
        this.suppPubInfo = Arrays.clone(suppPubInfo);
    }

    private ECCCMSSharedInfo(ASN1Sequence seq) {
        this.keyInfo = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        if (seq.size() == 2) {
            this.entityUInfo = null;
            this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
        } else {
            this.entityUInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(1), true).getOctets();
            this.suppPubInfo = ASN1OctetString.getInstance((ASN1TaggedObject)seq.getObjectAt(2), true).getOctets();
        }

    }

    public static ECCCMSSharedInfo getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static ECCCMSSharedInfo getInstance(Object obj) {
        if (obj instanceof ECCCMSSharedInfo) {
            return (ECCCMSSharedInfo)obj;
        } else {
            return obj != null ? new ECCCMSSharedInfo(ASN1Sequence.getInstance(obj)) : null;
        }
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.keyInfo);
        if (this.entityUInfo != null) {
            v.add(new DERTaggedObject(true, 0, new DEROctetString(this.entityUInfo)));
        }

        v.add(new DERTaggedObject(true, 2, new DEROctetString(this.suppPubInfo)));
        return new DERSequence(v);
    }
}
