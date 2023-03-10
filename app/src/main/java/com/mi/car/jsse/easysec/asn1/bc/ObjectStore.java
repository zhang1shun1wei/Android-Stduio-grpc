//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;

public class ObjectStore extends ASN1Object {
    private final ASN1Encodable storeData;
    private final ObjectStoreIntegrityCheck integrityCheck;

    public ObjectStore(ObjectStoreData objectStoreData, ObjectStoreIntegrityCheck integrityCheck) {
        this.storeData = objectStoreData;
        this.integrityCheck = integrityCheck;
    }

    public ObjectStore(EncryptedObjectStoreData encryptedObjectStoreData, ObjectStoreIntegrityCheck integrityCheck) {
        this.storeData = encryptedObjectStoreData;
        this.integrityCheck = integrityCheck;
    }

    private ObjectStore(ASN1Sequence seq) {
        if (seq.size() != 2) {
            throw new IllegalArgumentException("malformed sequence");
        } else {
            ASN1Encodable sData = seq.getObjectAt(0);
            if (sData instanceof EncryptedObjectStoreData) {
                this.storeData = sData;
            } else if (sData instanceof ObjectStoreData) {
                this.storeData = sData;
            } else {
                ASN1Sequence seqData = ASN1Sequence.getInstance(sData);
                if (seqData.size() == 2) {
                    this.storeData = EncryptedObjectStoreData.getInstance(seqData);
                } else {
                    this.storeData = ObjectStoreData.getInstance(seqData);
                }
            }

            this.integrityCheck = ObjectStoreIntegrityCheck.getInstance(seq.getObjectAt(1));
        }
    }

    public static ObjectStore getInstance(Object o) {
        if (o instanceof ObjectStore) {
            return (ObjectStore)o;
        } else {
            return o != null ? new ObjectStore(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public ObjectStoreIntegrityCheck getIntegrityCheck() {
        return this.integrityCheck;
    }

    public ASN1Encodable getStoreData() {
        return this.storeData;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.storeData);
        v.add(this.integrityCheck);
        return new DERSequence(v);
    }
}