//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.cmc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.cms.ContentInfo;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class EncryptedPOP extends ASN1Object {
    private final TaggedRequest request;
    private final ContentInfo cms;
    private final AlgorithmIdentifier thePOPAlgID;
    private final AlgorithmIdentifier witnessAlgID;
    private final byte[] witness;

    private EncryptedPOP(ASN1Sequence seq) {
        if (seq.size() != 5) {
            throw new IllegalArgumentException("incorrect sequence size");
        } else {
            this.request = TaggedRequest.getInstance(seq.getObjectAt(0));
            this.cms = ContentInfo.getInstance(seq.getObjectAt(1));
            this.thePOPAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
            this.witnessAlgID = AlgorithmIdentifier.getInstance(seq.getObjectAt(3));
            this.witness = Arrays.clone(ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets());
        }
    }

    public EncryptedPOP(TaggedRequest request, ContentInfo cms, AlgorithmIdentifier thePOPAlgID, AlgorithmIdentifier witnessAlgID, byte[] witness) {
        this.request = request;
        this.cms = cms;
        this.thePOPAlgID = thePOPAlgID;
        this.witnessAlgID = witnessAlgID;
        this.witness = Arrays.clone(witness);
    }

    public static EncryptedPOP getInstance(Object o) {
        if (o instanceof EncryptedPOP) {
            return (EncryptedPOP)o;
        } else {
            return o != null ? new EncryptedPOP(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public TaggedRequest getRequest() {
        return this.request;
    }

    public ContentInfo getCms() {
        return this.cms;
    }

    public AlgorithmIdentifier getThePOPAlgID() {
        return this.thePOPAlgID;
    }

    public AlgorithmIdentifier getWitnessAlgID() {
        return this.witnessAlgID;
    }

    public byte[] getWitness() {
        return Arrays.clone(this.witness);
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(5);
        v.add(this.request);
        v.add(this.cms);
        v.add(this.thePOPAlgID);
        v.add(this.witnessAlgID);
        v.add(new DEROctetString(this.witness));
        return new DERSequence(v);
    }
}