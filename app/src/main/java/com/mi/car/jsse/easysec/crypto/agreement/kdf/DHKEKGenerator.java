package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.asn1.ASN1Encodable;
import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Encoding;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.DERTaggedObject;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public class DHKEKGenerator implements DerivationFunction {
    private ASN1ObjectIdentifier algorithm;
    private final Digest digest;
    private int keySize;
    private byte[] partyAInfo;
    private byte[] z;

    public DHKEKGenerator(Digest digest2) {
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        DHKDFParameters params = (DHKDFParameters) param;
        this.algorithm = params.getAlgorithm();
        this.keySize = params.getKeySize();
        this.z = params.getZ();
        this.partyAInfo = params.getExtraInfo();
    }

    public Digest getDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (out.length - len < outOff) {
            throw new OutputLengthException("output buffer too small");
        }
        long oBytes = (long) len;
        int outLen = this.digest.getDigestSize();
        if (oBytes > 8589934591L) {
            throw new IllegalArgumentException("Output length too large");
        }
        int cThreshold = (int) (((((long) outLen) + oBytes) - 1) / ((long) outLen));
        byte[] dig = new byte[this.digest.getDigestSize()];
        int counter = 1;
        for (int i = 0; i < cThreshold; i++) {
            this.digest.update(this.z, 0, this.z.length);
            ASN1EncodableVector v1 = new ASN1EncodableVector();
            ASN1EncodableVector v2 = new ASN1EncodableVector();
            v2.add(this.algorithm);
            v2.add(new DEROctetString(Pack.intToBigEndian(counter)));
            v1.add(new DERSequence(v2));
            if (this.partyAInfo != null) {
                v1.add(new DERTaggedObject(true, 0, (ASN1Encodable) new DEROctetString(this.partyAInfo)));
            }
            v1.add(new DERTaggedObject(true, 2, (ASN1Encodable) new DEROctetString(Pack.intToBigEndian(this.keySize))));
            try {
                byte[] other = new DERSequence(v1).getEncoded(ASN1Encoding.DER);
                this.digest.update(other, 0, other.length);
                this.digest.doFinal(dig, 0);
                if (len > outLen) {
                    System.arraycopy(dig, 0, out, outOff, outLen);
                    outOff += outLen;
                    len -= outLen;
                } else {
                    System.arraycopy(dig, 0, out, outOff, len);
                }
                counter++;
            } catch (IOException e) {
                throw new IllegalArgumentException("unable to encode parameter info: " + e.getMessage());
            }
        }
        this.digest.reset();
        return (int) oBytes;
    }
}
