//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.pkcs.EncryptedPrivateKeyInfo;
import com.mi.car.jsse.easysec.asn1.x509.Certificate;

public class EncryptedPrivateKeyData extends ASN1Object {
    private final EncryptedPrivateKeyInfo encryptedPrivateKeyInfo;
    private final Certificate[] certificateChain;

    public EncryptedPrivateKeyData(EncryptedPrivateKeyInfo encryptedPrivateKeyInfo, Certificate[] certificateChain) {
        this.encryptedPrivateKeyInfo = encryptedPrivateKeyInfo;
        this.certificateChain = new Certificate[certificateChain.length];
        System.arraycopy(certificateChain, 0, this.certificateChain, 0, certificateChain.length);
    }

    private EncryptedPrivateKeyData(ASN1Sequence seq) {
        this.encryptedPrivateKeyInfo = EncryptedPrivateKeyInfo.getInstance(seq.getObjectAt(0));
        ASN1Sequence certSeq = ASN1Sequence.getInstance(seq.getObjectAt(1));
        this.certificateChain = new Certificate[certSeq.size()];

        for(int i = 0; i != this.certificateChain.length; ++i) {
            this.certificateChain[i] = Certificate.getInstance(certSeq.getObjectAt(i));
        }

    }

    public static EncryptedPrivateKeyData getInstance(Object o) {
        if (o instanceof EncryptedPrivateKeyData) {
            return (EncryptedPrivateKeyData)o;
        } else {
            return o != null ? new EncryptedPrivateKeyData(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public Certificate[] getCertificateChain() {
        Certificate[] tmp = new Certificate[this.certificateChain.length];
        System.arraycopy(this.certificateChain, 0, tmp, 0, this.certificateChain.length);
        return tmp;
    }

    public EncryptedPrivateKeyInfo getEncryptedPrivateKeyInfo() {
        return this.encryptedPrivateKeyInfo;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.encryptedPrivateKeyInfo);
        v.add(new DERSequence(this.certificateChain));
        return new DERSequence(v);
    }
}