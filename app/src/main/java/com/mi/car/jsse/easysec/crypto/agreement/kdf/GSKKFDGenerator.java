package com.mi.car.jsse.easysec.crypto.agreement.kdf;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.DigestDerivationFunction;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class GSKKFDGenerator implements DigestDerivationFunction {
    private byte[] buf;
    private int counter;
    private final Digest digest;
    private byte[] r;
    private byte[] z;

    public GSKKFDGenerator(Digest digest2) {
        this.digest = digest2;
        this.buf = new byte[digest2.getDigestSize()];
    }

    @Override // com.mi.car.jsse.easysec.crypto.DigestDerivationFunction
    public Digest getDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        if (param instanceof GSKKDFParameters) {
            this.z = ((GSKKDFParameters) param).getZ();
            this.counter = ((GSKKDFParameters) param).getStartCounter();
            this.r = ((GSKKDFParameters) param).getNonce();
            return;
        }
        throw new IllegalArgumentException("unkown parameters type");
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (outOff + len > out.length) {
            throw new DataLengthException("output buffer too small");
        }
        this.digest.update(this.z, 0, this.z.length);
        int i = this.counter;
        this.counter = i + 1;
        byte[] c = Pack.intToBigEndian(i);
        this.digest.update(c, 0, c.length);
        if (this.r != null) {
            this.digest.update(this.r, 0, this.r.length);
        }
        this.digest.doFinal(this.buf, 0);
        System.arraycopy(this.buf, 0, out, outOff, len);
        Arrays.clear(this.buf);
        return len;
    }
}
