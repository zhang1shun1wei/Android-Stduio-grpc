package com.mi.car.jsse.easysec.asn1.tsp;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

public class EvidenceRecord extends ASN1Object {
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.11.0.2.1");
    private ArchiveTimeStampSequence archiveTimeStampSequence;
    private CryptoInfos cryptoInfos;
    private ASN1Sequence digestAlgorithms;
    private EncryptionInfo encryptionInfo;
    private ASN1Integer version = new ASN1Integer(1);

    public static EvidenceRecord getInstance(Object obj) {
        if (obj instanceof EvidenceRecord) {
            return (EvidenceRecord) obj;
        }
        if (obj != null) {
            return new EvidenceRecord(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public static EvidenceRecord getInstance(ASN1TaggedObject tagged, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(tagged, explicit));
    }

    private EvidenceRecord(EvidenceRecord evidenceRecord, ArchiveTimeStampSequence replacementSequence, ArchiveTimeStamp newChainTimeStamp) {
        this.version = evidenceRecord.version;
        if (newChainTimeStamp != null) {
            AlgorithmIdentifier algId = newChainTimeStamp.getDigestAlgorithmIdentifier();
            ASN1EncodableVector vector = new ASN1EncodableVector();
            Enumeration enumeration = evidenceRecord.digestAlgorithms.getObjects();
            boolean found = false;
            while (true) {
                if (!enumeration.hasMoreElements()) {
                    break;
                }
                AlgorithmIdentifier algorithmIdentifier = AlgorithmIdentifier.getInstance(enumeration.nextElement());
                vector.add(algorithmIdentifier);
                if (algorithmIdentifier.equals(algId)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                vector.add(algId);
                this.digestAlgorithms = new DERSequence(vector);
            } else {
                this.digestAlgorithms = evidenceRecord.digestAlgorithms;
            }
        } else {
            this.digestAlgorithms = evidenceRecord.digestAlgorithms;
        }
        this.cryptoInfos = evidenceRecord.cryptoInfos;
        this.encryptionInfo = evidenceRecord.encryptionInfo;
        this.archiveTimeStampSequence = replacementSequence;
    }

    public EvidenceRecord(CryptoInfos cryptoInfos2, EncryptionInfo encryptionInfo2, ArchiveTimeStamp archiveTimeStamp) {
        this.digestAlgorithms = new DERSequence(archiveTimeStamp.getDigestAlgorithmIdentifier());
        this.cryptoInfos = cryptoInfos2;
        this.encryptionInfo = encryptionInfo2;
        this.archiveTimeStampSequence = new ArchiveTimeStampSequence(new ArchiveTimeStampChain(archiveTimeStamp));
    }

    public EvidenceRecord(AlgorithmIdentifier[] digestAlgorithms2, CryptoInfos cryptoInfos2, EncryptionInfo encryptionInfo2, ArchiveTimeStampSequence archiveTimeStampSequence2) {
        this.digestAlgorithms = new DERSequence(digestAlgorithms2);
        this.cryptoInfos = cryptoInfos2;
        this.encryptionInfo = encryptionInfo2;
        this.archiveTimeStampSequence = archiveTimeStampSequence2;
    }

    private EvidenceRecord(ASN1Sequence sequence) {
        if (sequence.size() >= 3 || sequence.size() <= 5) {
            ASN1Integer versionNumber = ASN1Integer.getInstance(sequence.getObjectAt(0));
            if (!versionNumber.hasValue(1)) {
                throw new IllegalArgumentException("incompatible version");
            }
            this.version = versionNumber;
            this.digestAlgorithms = ASN1Sequence.getInstance(sequence.getObjectAt(1));
            for (int i = 2; i != sequence.size() - 1; i++) {
                ASN1Encodable object = sequence.getObjectAt(i);
                if (object instanceof ASN1TaggedObject) {
                    ASN1TaggedObject asn1TaggedObject = (ASN1TaggedObject) object;
                    switch (asn1TaggedObject.getTagNo()) {
                        case 0:
                            this.cryptoInfos = CryptoInfos.getInstance(asn1TaggedObject, false);
                            break;
                        case 1:
                            this.encryptionInfo = EncryptionInfo.getInstance(asn1TaggedObject, false);
                            break;
                        default:
                            throw new IllegalArgumentException("unknown tag in getInstance: " + asn1TaggedObject.getTagNo());
                    }
                } else {
                    throw new IllegalArgumentException("unknown object in getInstance: " + object.getClass().getName());
                }
            }
            this.archiveTimeStampSequence = ArchiveTimeStampSequence.getInstance(sequence.getObjectAt(sequence.size() - 1));
            return;
        }
        throw new IllegalArgumentException("wrong sequence size in constructor: " + sequence.size());
    }

    public AlgorithmIdentifier[] getDigestAlgorithms() {
        AlgorithmIdentifier[] rv = new AlgorithmIdentifier[this.digestAlgorithms.size()];
        for (int i = 0; i != rv.length; i++) {
            rv[i] = AlgorithmIdentifier.getInstance(this.digestAlgorithms.getObjectAt(i));
        }
        return rv;
    }

    public ArchiveTimeStampSequence getArchiveTimeStampSequence() {
        return this.archiveTimeStampSequence;
    }

    public EvidenceRecord addArchiveTimeStamp(ArchiveTimeStamp ats, boolean newChain) {
        if (newChain) {
            return new EvidenceRecord(this, this.archiveTimeStampSequence.append(new ArchiveTimeStampChain(ats)), ats);
        }
        ArchiveTimeStampChain[] chains = this.archiveTimeStampSequence.getArchiveTimeStampChains();
        chains[chains.length - 1] = chains[chains.length - 1].append(ats);
        return new EvidenceRecord(this, new ArchiveTimeStampSequence(chains), (ArchiveTimeStamp) null);
    }

    public String toString() {
        return "EvidenceRecord: Oid(" + OID + ")";
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector vector = new ASN1EncodableVector(5);
        vector.add(this.version);
        vector.add(this.digestAlgorithms);
        if (this.cryptoInfos != null) {
            vector.add(new DERTaggedObject(false, 0, this.cryptoInfos));
        }
        if (this.encryptionInfo != null) {
            vector.add(new DERTaggedObject(false, 1, this.encryptionInfo));
        }
        vector.add(this.archiveTimeStampSequence);
        return new DERSequence(vector);
    }
}
