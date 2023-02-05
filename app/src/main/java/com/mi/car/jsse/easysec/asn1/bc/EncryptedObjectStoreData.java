//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class EncryptedObjectStoreData extends ASN1Object {
    private final AlgorithmIdentifier encryptionAlgorithm;
    private final ASN1OctetString encryptedContent;

    public EncryptedObjectStoreData(AlgorithmIdentifier encryptionAlgorithm, byte[] encryptedContent) {
        this.encryptionAlgorithm = encryptionAlgorithm;
        this.encryptedContent = new DEROctetString(Arrays.clone(encryptedContent));
    }

    private EncryptedObjectStoreData(ASN1Sequence seq) {
        this.encryptionAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.encryptedContent = ASN1OctetString.getInstance(seq.getObjectAt(1));
    }

    public static EncryptedObjectStoreData getInstance(Object o) {
        if (o instanceof EncryptedObjectStoreData) {
            return (EncryptedObjectStoreData)o;
        } else {
            return o != null ? new EncryptedObjectStoreData(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ASN1OctetString getEncryptedContent() {
        return this.encryptedContent;
    }

    public AlgorithmIdentifier getEncryptionAlgorithm() {
        return this.encryptionAlgorithm;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.encryptionAlgorithm);
        v.add(this.encryptedContent);
        return new DERSequence(v);
    }
}