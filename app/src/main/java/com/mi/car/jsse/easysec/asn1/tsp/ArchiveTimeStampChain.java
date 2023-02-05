package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import java.util.Enumeration;

public class ArchiveTimeStampChain extends ASN1Object {
    private ASN1Sequence archiveTimestamps;

    public static ArchiveTimeStampChain getInstance(Object obj) {
        if (obj instanceof ArchiveTimeStampChain) {
            return (ArchiveTimeStampChain) obj;
        }
        if (obj != null) {
            return new ArchiveTimeStampChain(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp archiveTimeStamp) {
        this.archiveTimestamps = new DERSequence(archiveTimeStamp);
    }

    public ArchiveTimeStampChain(ArchiveTimeStamp[] archiveTimeStamps) {
        this.archiveTimestamps = new DERSequence(archiveTimeStamps);
    }

    private ArchiveTimeStampChain(ASN1Sequence sequence) {
        ASN1EncodableVector vector = new ASN1EncodableVector(sequence.size());
        Enumeration objects = sequence.getObjects();
        while (objects.hasMoreElements()) {
            vector.add(ArchiveTimeStamp.getInstance(objects.nextElement()));
        }
        this.archiveTimestamps = new DERSequence(vector);
    }

    public ArchiveTimeStamp[] getArchiveTimestamps() {
        ArchiveTimeStamp[] rv = new ArchiveTimeStamp[this.archiveTimestamps.size()];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = ArchiveTimeStamp.getInstance(this.archiveTimestamps.getObjectAt(i));
        }
        return rv;
    }

    public ArchiveTimeStampChain append(ArchiveTimeStamp archiveTimeStamp) {
        ASN1EncodableVector v = new ASN1EncodableVector(this.archiveTimestamps.size() + 1);
        for (int i = 0; i != this.archiveTimestamps.size(); i++) {
            v.add(this.archiveTimestamps.getObjectAt(i));
        }
        v.add(archiveTimeStamp);
        return new ArchiveTimeStampChain((ASN1Sequence) new DERSequence(v));
    }

    public ASN1Primitive toASN1Primitive() {
        return this.archiveTimestamps;
    }
}
