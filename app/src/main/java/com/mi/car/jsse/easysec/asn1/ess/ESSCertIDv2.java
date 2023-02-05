package com.mi.car.jsse.easysec.asn1.ess;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.asn1.x509.IssuerSerial;
import com.mi.car.jsse.easysec.util.Arrays;

public class ESSCertIDv2 extends ASN1Object {
    private static final AlgorithmIdentifier DEFAULT_ALG_ID = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
    private byte[] certHash;
    private AlgorithmIdentifier hashAlgorithm;
    private IssuerSerial issuerSerial;

    public static ESSCertIDv2 getInstance(Object o) {
        if (o instanceof ESSCertIDv2) {
            return (ESSCertIDv2) o;
        }
        if (o != null) {
            return new ESSCertIDv2(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    private ESSCertIDv2(ASN1Sequence seq) {
        if (seq.size() > 3) {
            throw new IllegalArgumentException("Bad sequence size: " + seq.size());
        }
        int count = 0;
        if (seq.getObjectAt(0) instanceof ASN1OctetString) {
            this.hashAlgorithm = DEFAULT_ALG_ID;
        } else {
            this.hashAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0).toASN1Primitive());
            count = 0 + 1;
        }
        int count2 = count + 1;
        this.certHash = ASN1OctetString.getInstance(seq.getObjectAt(count).toASN1Primitive()).getOctets();
        if (seq.size() > count2) {
            this.issuerSerial = IssuerSerial.getInstance(seq.getObjectAt(count2));
        }
    }

    public ESSCertIDv2(byte[] certHash2) {
        this(null, certHash2, null);
    }

    public ESSCertIDv2(AlgorithmIdentifier algId, byte[] certHash2) {
        this(algId, certHash2, null);
    }

    public ESSCertIDv2(byte[] certHash2, IssuerSerial issuerSerial2) {
        this(null, certHash2, issuerSerial2);
    }

    public ESSCertIDv2(AlgorithmIdentifier algId, byte[] certHash2, IssuerSerial issuerSerial2) {
        if (algId == null) {
            this.hashAlgorithm = DEFAULT_ALG_ID;
        } else {
            this.hashAlgorithm = algId;
        }
        this.certHash = Arrays.clone(certHash2);
        this.issuerSerial = issuerSerial2;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public byte[] getCertHash() {
        return Arrays.clone(this.certHash);
    }

    public IssuerSerial getIssuerSerial() {
        return this.issuerSerial;
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        if (!this.hashAlgorithm.equals(DEFAULT_ALG_ID)) {
            v.add(this.hashAlgorithm);
        }
        v.add(new DEROctetString(this.certHash).toASN1Primitive());
        if (this.issuerSerial != null) {
            v.add(this.issuerSerial);
        }
        return new DERSequence(v);
    }
}
