package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class ArchiveTimeStampSequence extends ASN1Object {
    private ASN1Sequence archiveTimeStampChains;

    public static ArchiveTimeStampSequence getInstance(Object obj) {
        if (obj instanceof ArchiveTimeStampChain) {
            return (ArchiveTimeStampSequence) obj;
        }
        if (obj != null) {
            return new ArchiveTimeStampSequence(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private ArchiveTimeStampSequence(ASN1Sequence sequence) throws IllegalArgumentException {
        ASN1EncodableVector vector = new ASN1EncodableVector(sequence.size());
        Enumeration objects = sequence.getObjects();
        while (objects.hasMoreElements()) {
            vector.add(ArchiveTimeStampChain.getInstance(objects.nextElement()));
        }
        this.archiveTimeStampChains = new DERSequence(vector);
    }

    public ArchiveTimeStampSequence(ArchiveTimeStampChain archiveTimeStampChain) {
        this.archiveTimeStampChains = new DERSequence(archiveTimeStampChain);
    }

    public ArchiveTimeStampSequence(ArchiveTimeStampChain[] archiveTimeStampChains2) {
        this.archiveTimeStampChains = new DERSequence(archiveTimeStampChains2);
    }

    public ArchiveTimeStampChain[] getArchiveTimeStampChains() {
        ArchiveTimeStampChain[] rv = new ArchiveTimeStampChain[this.archiveTimeStampChains.size()];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = ArchiveTimeStampChain.getInstance(this.archiveTimeStampChains.getObjectAt(i));
        }
        return rv;
    }

    public int size() {
        return this.archiveTimeStampChains.size();
    }

    public ArchiveTimeStampSequence append(ArchiveTimeStampChain chain) {
        ASN1EncodableVector v = new ASN1EncodableVector(this.archiveTimeStampChains.size() + 1);
        for (int i = 0; i != this.archiveTimeStampChains.size(); i++) {
            v.add(this.archiveTimeStampChains.getObjectAt(i));
        }
        v.add(chain);
        return new ArchiveTimeStampSequence((ASN1Sequence) new DERSequence(v));
    }

    public ASN1Primitive toASN1Primitive() {
        return this.archiveTimeStampChains;
    }
}
