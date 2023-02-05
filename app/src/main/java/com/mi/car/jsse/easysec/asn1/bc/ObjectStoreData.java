//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1UTF8String;
import com.mi.car.jsse.easysec.asn1.DERGeneralizedTime;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERUTF8String;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.math.BigInteger;
import java.util.Date;

public class ObjectStoreData extends ASN1Object {
    private final BigInteger version;
    private final AlgorithmIdentifier integrityAlgorithm;
    private final ASN1GeneralizedTime creationDate;
    private final ASN1GeneralizedTime lastModifiedDate;
    private final ObjectDataSequence objectDataSequence;
    private final String comment;

    public ObjectStoreData(AlgorithmIdentifier integrityAlgorithm, Date creationDate, Date lastModifiedDate, ObjectDataSequence objectDataSequence, String comment) {
        this.version = BigInteger.valueOf(1L);
        this.integrityAlgorithm = integrityAlgorithm;
        this.creationDate = new DERGeneralizedTime(creationDate);
        this.lastModifiedDate = new DERGeneralizedTime(lastModifiedDate);
        this.objectDataSequence = objectDataSequence;
        this.comment = comment;
    }

    private ObjectStoreData(ASN1Sequence seq) {
        this.version = ASN1Integer.getInstance(seq.getObjectAt(0)).getValue();
        this.integrityAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
        this.creationDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(2));
        this.lastModifiedDate = ASN1GeneralizedTime.getInstance(seq.getObjectAt(3));
        this.objectDataSequence = ObjectDataSequence.getInstance(seq.getObjectAt(4));
        this.comment = seq.size() == 6 ? ASN1UTF8String.getInstance(seq.getObjectAt(5)).getString() : null;
    }

    public static ObjectStoreData getInstance(Object o) {
        if (o instanceof ObjectStoreData) {
            return (ObjectStoreData)o;
        } else {
            return o != null ? new ObjectStoreData(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public String getComment() {
        return this.comment;
    }

    public ASN1GeneralizedTime getCreationDate() {
        return this.creationDate;
    }

    public AlgorithmIdentifier getIntegrityAlgorithm() {
        return this.integrityAlgorithm;
    }

    public ASN1GeneralizedTime getLastModifiedDate() {
        return this.lastModifiedDate;
    }

    public ObjectDataSequence getObjectDataSequence() {
        return this.objectDataSequence;
    }

    public BigInteger getVersion() {
        return this.version;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(6);
        v.add(new ASN1Integer(this.version));
        v.add(this.integrityAlgorithm);
        v.add(this.creationDate);
        v.add(this.lastModifiedDate);
        v.add(this.objectDataSequence);
        if (this.comment != null) {
            v.add(new DERUTF8String(this.comment));
        }

        return new DERSequence(v);
    }
}