package com.mi.car.jsse.easysec.asn1.pkcs;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.ASN1TaggedObject;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.math.BigInteger;

public class RSASSAPSSparams extends ASN1Object {
    public static final AlgorithmIdentifier DEFAULT_HASH_ALGORITHM = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);
    public static final AlgorithmIdentifier DEFAULT_MASK_GEN_FUNCTION = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, DEFAULT_HASH_ALGORITHM);
    public static final ASN1Integer DEFAULT_SALT_LENGTH = new ASN1Integer(20);
    public static final ASN1Integer DEFAULT_TRAILER_FIELD = new ASN1Integer(1);
    private AlgorithmIdentifier hashAlgorithm;
    private AlgorithmIdentifier maskGenAlgorithm;
    private ASN1Integer saltLength;
    private ASN1Integer trailerField;

    public static RSASSAPSSparams getInstance(Object obj) {
        if (obj instanceof RSASSAPSSparams) {
            return (RSASSAPSSparams) obj;
        }
        if (obj != null) {
            return new RSASSAPSSparams(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    public RSASSAPSSparams() {
        this.hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        this.maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        this.saltLength = DEFAULT_SALT_LENGTH;
        this.trailerField = DEFAULT_TRAILER_FIELD;
    }

    public RSASSAPSSparams(AlgorithmIdentifier hashAlgorithm2, AlgorithmIdentifier maskGenAlgorithm2, ASN1Integer saltLength2, ASN1Integer trailerField2) {
        this.hashAlgorithm = hashAlgorithm2;
        this.maskGenAlgorithm = maskGenAlgorithm2;
        this.saltLength = saltLength2;
        this.trailerField = trailerField2;
    }

    private RSASSAPSSparams(ASN1Sequence seq) {
        this.hashAlgorithm = DEFAULT_HASH_ALGORITHM;
        this.maskGenAlgorithm = DEFAULT_MASK_GEN_FUNCTION;
        this.saltLength = DEFAULT_SALT_LENGTH;
        this.trailerField = DEFAULT_TRAILER_FIELD;
        for (int i = 0; i != seq.size(); i++) {
            ASN1TaggedObject o = (ASN1TaggedObject) seq.getObjectAt(i);
            switch (o.getTagNo()) {
                case 0:
                    this.hashAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                    break;
                case 1:
                    this.maskGenAlgorithm = AlgorithmIdentifier.getInstance(o, true);
                    break;
                case 2:
                    this.saltLength = ASN1Integer.getInstance(o, true);
                    break;
                case 3:
                    this.trailerField = ASN1Integer.getInstance(o, true);
                    break;
                default:
                    throw new IllegalArgumentException("unknown tag");
            }
        }
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public AlgorithmIdentifier getMaskGenAlgorithm() {
        return this.maskGenAlgorithm;
    }

    public BigInteger getSaltLength() {
        return this.saltLength.getValue();
    }

    public BigInteger getTrailerField() {
        return this.trailerField.getValue();
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(4);
        if (!this.hashAlgorithm.equals(DEFAULT_HASH_ALGORITHM)) {
            v.add(new DERTaggedObject(true, 0, (ASN1Encodable) this.hashAlgorithm));
        }
        if (!this.maskGenAlgorithm.equals(DEFAULT_MASK_GEN_FUNCTION)) {
            v.add(new DERTaggedObject(true, 1, (ASN1Encodable) this.maskGenAlgorithm));
        }
        if (!this.saltLength.equals((ASN1Primitive) DEFAULT_SALT_LENGTH)) {
            v.add(new DERTaggedObject(true, 2, (ASN1Encodable) this.saltLength));
        }
        if (!this.trailerField.equals((ASN1Primitive) DEFAULT_TRAILER_FIELD)) {
            v.add(new DERTaggedObject(true, 3, (ASN1Encodable) this.trailerField));
        }
        return new DERSequence(v);
    }
}
