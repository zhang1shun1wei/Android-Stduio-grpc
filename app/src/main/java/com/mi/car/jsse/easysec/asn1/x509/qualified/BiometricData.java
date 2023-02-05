package com.mi.car.jsse.easysec.asn1.x509.qualified;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1IA5String;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERIA5String;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import java.util.Enumeration;

public class BiometricData extends ASN1Object {
    private ASN1OctetString biometricDataHash;
    private AlgorithmIdentifier hashAlgorithm;
    private ASN1IA5String sourceDataUri;
    private TypeOfBiometricData typeOfBiometricData;

    public static BiometricData getInstance(Object obj) {
        if (obj instanceof BiometricData) {
            return (BiometricData) obj;
        }
        if (obj != null) {
            return new BiometricData(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private BiometricData(ASN1Sequence seq) {
        Enumeration e = seq.getObjects();
        this.typeOfBiometricData = TypeOfBiometricData.getInstance(e.nextElement());
        this.hashAlgorithm = AlgorithmIdentifier.getInstance(e.nextElement());
        this.biometricDataHash = ASN1OctetString.getInstance(e.nextElement());
        if (e.hasMoreElements()) {
            this.sourceDataUri = ASN1IA5String.getInstance(e.nextElement());
        }
    }

    public BiometricData(TypeOfBiometricData typeOfBiometricData2, AlgorithmIdentifier hashAlgorithm2, ASN1OctetString biometricDataHash2, ASN1IA5String sourceDataUri2) {
        this.typeOfBiometricData = typeOfBiometricData2;
        this.hashAlgorithm = hashAlgorithm2;
        this.biometricDataHash = biometricDataHash2;
        this.sourceDataUri = sourceDataUri2;
    }

    public BiometricData(TypeOfBiometricData typeOfBiometricData2, AlgorithmIdentifier hashAlgorithm2, ASN1OctetString biometricDataHash2) {
        this.typeOfBiometricData = typeOfBiometricData2;
        this.hashAlgorithm = hashAlgorithm2;
        this.biometricDataHash = biometricDataHash2;
        this.sourceDataUri = null;
    }

    public TypeOfBiometricData getTypeOfBiometricData() {
        return this.typeOfBiometricData;
    }

    public AlgorithmIdentifier getHashAlgorithm() {
        return this.hashAlgorithm;
    }

    public ASN1OctetString getBiometricDataHash() {
        return this.biometricDataHash;
    }

    public DERIA5String getSourceDataUri() {
        if (this.sourceDataUri == null || (this.sourceDataUri instanceof DERIA5String)) {
            return (DERIA5String) this.sourceDataUri;
        }
        return new DERIA5String(this.sourceDataUri.getString(), false);
    }

    public ASN1IA5String getSourceDataUriIA5() {
        return this.sourceDataUri;
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector seq = new ASN1EncodableVector(4);
        seq.add(this.typeOfBiometricData);
        seq.add(this.hashAlgorithm);
        seq.add(this.biometricDataHash);
        if (this.sourceDataUri != null) {
            seq.add(this.sourceDataUri);
        }
        return new DERSequence(seq);
    }
}
