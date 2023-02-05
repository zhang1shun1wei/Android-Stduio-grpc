package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DERNull;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.DigestDerivationFunction;
import com.mi.car.jsse.easysec.crypto.generators.KDF2BytesGenerator;
import com.mi.car.jsse.easysec.crypto.params.KDFParameters;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public class ECDHKEKGenerator implements DigestDerivationFunction {
    private ASN1ObjectIdentifier algorithm;
    private DigestDerivationFunction kdf;
    private int keySize;
    private byte[] z;

    public ECDHKEKGenerator(Digest digest) {
        this.kdf = new KDF2BytesGenerator(digest);
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        DHKDFParameters params = (DHKDFParameters) param;
        this.algorithm = params.getAlgorithm();
        this.keySize = params.getKeySize();
        this.z = params.getZ();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DigestDerivationFunction
    public Digest getDigest() {
        return this.kdf.getDigest();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (outOff + len > out.length) {
            throw new DataLengthException("output buffer too small");
        }
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new AlgorithmIdentifier(this.algorithm, DERNull.INSTANCE));
        v.add(new DERTaggedObject(true, 2, (ASN1Encodable) new DEROctetString(Pack.intToBigEndian(this.keySize))));
        try {
            this.kdf.init(new KDFParameters(this.z, new DERSequence(v).getEncoded(ASN1Encoding.DER)));
            return this.kdf.generateBytes(out, outOff, len);
        } catch (IOException e) {
            throw new IllegalArgumentException("unable to initialise kdf: " + e.getMessage());
        }
    }
}
