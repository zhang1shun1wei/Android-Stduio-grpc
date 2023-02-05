package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.DigestInfo;
import com.mi.car.jsse.easysec.asn1.x509.IssuerSerial;

public class OtherCertID extends ASN1Object {
    private ASN1Encodable otherCertHash;
    private IssuerSerial issuerSerial;

    public static OtherCertID getInstance(Object o) {
        if (o instanceof OtherCertID) {
            return (OtherCertID)o;
        } else {
            return o != null ? new OtherCertID(ASN1Sequence.getInstance(o)) : null;
        }
    }

    private OtherCertID(ASN1Sequence seq) {
        if (seq.size() >= 1 && seq.size() <= 2) {
            if (seq.getObjectAt(0).toASN1Primitive() instanceof ASN1OctetString) {
                this.otherCertHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
            } else {
                this.otherCertHash = DigestInfo.getInstance(seq.getObjectAt(0));
            }

            if (seq.size() > 1) {
                this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(1));
            }

        } else {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
    }

    public OtherCertID(AlgorithmIdentifier algId, byte[] digest) {
        this.otherCertHash = new DigestInfo(algId, digest);
    }

    public OtherCertID(AlgorithmIdentifier algId, byte[] digest, IssuerSerial issuerSerial) {
        this.otherCertHash = new DigestInfo(algId, digest);
        this.issuerSerial = issuerSerial;
    }

    public AlgorithmIdentifier getAlgorithmHash() {
        return this.otherCertHash.toASN1Primitive() instanceof ASN1OctetString ? new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1) : DigestInfo.getInstance(this.otherCertHash).getAlgorithmId();
    }

    public byte[] getCertHash() {
        return this.otherCertHash.toASN1Primitive() instanceof ASN1OctetString ? ((ASN1OctetString)this.otherCertHash.toASN1Primitive()).getOctets() : DigestInfo.getInstance(this.otherCertHash).getDigest();
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(2);
        v.add(this.otherCertHash);
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }

        return new DERSequence(v);
    }
}
