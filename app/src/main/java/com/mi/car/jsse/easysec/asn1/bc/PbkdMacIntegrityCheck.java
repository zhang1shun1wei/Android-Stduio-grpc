//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.asn1.bc;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.pkcs.KeyDerivationFunc;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.util.Arrays;

public class PbkdMacIntegrityCheck extends ASN1Object {
    private final AlgorithmIdentifier macAlgorithm;
    private final KeyDerivationFunc pbkdAlgorithm;
    private final ASN1OctetString mac;

    public PbkdMacIntegrityCheck(AlgorithmIdentifier macAlgorithm, KeyDerivationFunc pbkdAlgorithm, byte[] mac) {
        this.macAlgorithm = macAlgorithm;
        this.pbkdAlgorithm = pbkdAlgorithm;
        this.mac = new DEROctetString(Arrays.clone(mac));
    }

    private PbkdMacIntegrityCheck(ASN1Sequence seq) {
        this.macAlgorithm = AlgorithmIdentifier.getInstance(seq.getObjectAt(0));
        this.pbkdAlgorithm = KeyDerivationFunc.getInstance(seq.getObjectAt(1));
        this.mac = ASN1OctetString.getInstance(seq.getObjectAt(2));
    }

    public static PbkdMacIntegrityCheck getInstance(Object o) {
        if (o instanceof PbkdMacIntegrityCheck) {
            return (PbkdMacIntegrityCheck)o;
        } else {
            return o != null ? new PbkdMacIntegrityCheck(ASN1Sequence.getInstance(o)) : null;
        }
    }

    public AlgorithmIdentifier getMacAlgorithm() {
        return this.macAlgorithm;
    }

    public KeyDerivationFunc getPbkdAlgorithm() {
        return this.pbkdAlgorithm;
    }

    public byte[] getMac() {
        return Arrays.clone(this.mac.getOctets());
    }

    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector(3);
        v.add(this.macAlgorithm);
        v.add(this.pbkdAlgorithm);
        v.add(this.mac);
        return new DERSequence(v);
    }
}