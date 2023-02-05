package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.DerivationFunction;
import com.mi.car.jsse.easysec.crypto.DerivationParameters;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KDFParameters;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class BrokenKDF2BytesGenerator implements DerivationFunction {
    private Digest digest;
    private byte[] iv;
    private byte[] shared;

    public BrokenKDF2BytesGenerator(Digest digest2) {
        this.digest = digest2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public void init(DerivationParameters param) {
        if (!(param instanceof KDFParameters)) {
            throw new IllegalArgumentException("KDF parameters required for generator");
        }
        KDFParameters p = (KDFParameters) param;
        this.shared = p.getSharedSecret();
        this.iv = p.getIV();
    }

    public Digest getDigest() {
        return this.digest;
    }

    @Override // com.mi.car.jsse.easysec.crypto.DerivationFunction
    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException, IllegalArgumentException {
        if (out.length - len < outOff) {
            throw new OutputLengthException("output buffer too small");
        }
        long oBits = ((long) len) * 8;
        if (oBits > ((long) this.digest.getDigestSize()) * 8 * 2147483648L) {
            throw new IllegalArgumentException("Output length too large");
        }
        int cThreshold = (int) (oBits / ((long) this.digest.getDigestSize()));
        byte[] dig = new byte[this.digest.getDigestSize()];
        for (int counter = 1; counter <= cThreshold; counter++) {
            this.digest.update(this.shared, 0, this.shared.length);
            this.digest.update((byte) (counter & GF2Field.MASK));
            this.digest.update((byte) ((counter >> 8) & GF2Field.MASK));
            this.digest.update((byte) ((counter >> 16) & GF2Field.MASK));
            this.digest.update((byte) ((counter >> 24) & GF2Field.MASK));
            this.digest.update(this.iv, 0, this.iv.length);
            this.digest.doFinal(dig, 0);
            if (len - outOff > dig.length) {
                System.arraycopy(dig, 0, out, outOff, dig.length);
                outOff += dig.length;
            } else {
                System.arraycopy(dig, 0, out, outOff, len - outOff);
            }
        }
        this.digest.reset();
        return len;
    }
}
