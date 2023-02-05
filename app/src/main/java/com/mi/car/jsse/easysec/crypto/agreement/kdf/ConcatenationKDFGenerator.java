package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KDFParameters;

public class ConcatenationKDFGenerator implements DerivationFunction {
    private Digest digest;
    private int hLen;
    private byte[] otherInfo;
    private byte[] shared;

    public ConcatenationKDFGenerator(Digest digest2) {
        this.digest = digest2;
        this.hLen = digest2.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        if (param instanceof KDFParameters) {
            KDFParameters p = (KDFParameters) param;
            this.shared = p.getSharedSecret();
            this.otherInfo = p.getIV();
            return;
        }
        throw new IllegalArgumentException("KDF parameters required for generator");
    }

    public Digest getDigest() {
        return this.digest;
    }

    private void ItoOSP(int i, byte[] sp) {
        sp[0] = (byte) (i >>> 24);
        sp[1] = (byte) (i >>> 16);
        sp[2] = (byte) (i >>> 8);
        sp[3] = (byte) (i >>> 0);
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        int counter;
        if (out.length - len < outOff) {
            throw new OutputLengthException("output buffer too small");
        }
        byte[] hashBuf = new byte[this.hLen];
        byte[] C = new byte[4];
        int counter2 = 1;
        int outputLen = 0;
        this.digest.reset();
        if (len > this.hLen) {
            while (true) {
                ItoOSP(counter2, C);
                this.digest.update(C, 0, C.length);
                this.digest.update(this.shared, 0, this.shared.length);
                this.digest.update(this.otherInfo, 0, this.otherInfo.length);
                this.digest.doFinal(hashBuf, 0);
                System.arraycopy(hashBuf, 0, out, outOff + outputLen, this.hLen);
                outputLen += this.hLen;
                counter = counter2 + 1;
                if (counter2 >= len / this.hLen) {
                    break;
                }
                counter2 = counter;
            }
            counter2 = counter;
        }
        if (outputLen < len) {
            ItoOSP(counter2, C);
            this.digest.update(C, 0, C.length);
            this.digest.update(this.shared, 0, this.shared.length);
            this.digest.update(this.otherInfo, 0, this.otherInfo.length);
            this.digest.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, out, outOff + outputLen, len - outputLen);
        }
        return len;
    }
}
