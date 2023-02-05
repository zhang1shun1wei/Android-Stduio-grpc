package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.MGFParameters;

public class MGF1BytesGenerator implements DerivationFunction {
    private Digest digest;
    private int hLen;
    private byte[] seed;

    public MGF1BytesGenerator(Digest digest2) {
        this.digest = digest2;
        this.hLen = digest2.getDigestSize();
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        if (!(param instanceof MGFParameters)) {
            throw new IllegalArgumentException("MGF parameters required for MGF1Generator");
        }
        this.seed = ((MGFParameters) param).getSeed();
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
        if (out.length - len < outOff) {
            throw new OutputLengthException("output buffer too small");
        }
        byte[] hashBuf = new byte[this.hLen];
        byte[] C = new byte[4];
        int counter = 0;
        this.digest.reset();
        if (len > this.hLen) {
            do {
                ItoOSP(counter, C);
                this.digest.update(this.seed, 0, this.seed.length);
                this.digest.update(C, 0, C.length);
                this.digest.doFinal(hashBuf, 0);
                System.arraycopy(hashBuf, 0, out, (this.hLen * counter) + outOff, this.hLen);
                counter++;
            } while (counter < len / this.hLen);
        }
        if (this.hLen * counter < len) {
            ItoOSP(counter, C);
            this.digest.update(this.seed, 0, this.seed.length);
            this.digest.update(C, 0, C.length);
            this.digest.doFinal(hashBuf, 0);
            System.arraycopy(hashBuf, 0, out, (this.hLen * counter) + outOff, len - (this.hLen * counter));
        }
        return len;
    }
}
