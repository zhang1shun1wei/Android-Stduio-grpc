package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.crypto.BlockCipher;

public class X931RNG {
    private static final int BLOCK128_MAX_BITS_REQUEST = 262144;
    private static final long BLOCK128_RESEED_MAX = 8388608;
    private static final int BLOCK64_MAX_BITS_REQUEST = 4096;
    private static final long BLOCK64_RESEED_MAX = 32768;
    private final byte[] DT;
    private final byte[] I;
    private final byte[] R;
    private byte[] V;
    private final BlockCipher engine;
    private final EntropySource entropySource;
    private long reseedCounter = 1;

    public X931RNG(BlockCipher engine2, byte[] dateTimeVector, EntropySource entropySource2) {
        this.engine = engine2;
        this.entropySource = entropySource2;
        this.DT = new byte[engine2.getBlockSize()];
        System.arraycopy(dateTimeVector, 0, this.DT, 0, this.DT.length);
        this.I = new byte[engine2.getBlockSize()];
        this.R = new byte[engine2.getBlockSize()];
    }

    /* access modifiers changed from: package-private */
    public int generate(byte[] output, boolean predictionResistant) {
        if (this.R.length == 8) {
            if (this.reseedCounter > BLOCK64_RESEED_MAX) {
                return -1;
            }
            if (isTooLarge(output, 512)) {
                throw new IllegalArgumentException("Number of bits per request limited to 4096");
            }
        } else if (this.reseedCounter > BLOCK128_RESEED_MAX) {
            return -1;
        } else {
            if (isTooLarge(output, 32768)) {
                throw new IllegalArgumentException("Number of bits per request limited to 262144");
            }
        }
        if (predictionResistant || this.V == null) {
            this.V = this.entropySource.getEntropy();
            if (this.V.length != this.engine.getBlockSize()) {
                throw new IllegalStateException("Insufficient entropy returned");
            }
        }
        int m = output.length / this.R.length;
        for (int i = 0; i < m; i++) {
            this.engine.processBlock(this.DT, 0, this.I, 0);
            process(this.R, this.I, this.V);
            process(this.V, this.R, this.I);
            System.arraycopy(this.R, 0, output, this.R.length * i, this.R.length);
            increment(this.DT);
        }
        int bytesToCopy = output.length - (this.R.length * m);
        if (bytesToCopy > 0) {
            this.engine.processBlock(this.DT, 0, this.I, 0);
            process(this.R, this.I, this.V);
            process(this.V, this.R, this.I);
            System.arraycopy(this.R, 0, output, this.R.length * m, bytesToCopy);
            increment(this.DT);
        }
        this.reseedCounter++;
        return output.length;
    }

    /* access modifiers changed from: package-private */
    public void reseed() {
        this.V = this.entropySource.getEntropy();
        if (this.V.length != this.engine.getBlockSize()) {
            throw new IllegalStateException("Insufficient entropy returned");
        }
        this.reseedCounter = 1;
    }

    /* access modifiers changed from: package-private */
    public EntropySource getEntropySource() {
        return this.entropySource;
    }

    private void process(byte[] res, byte[] a, byte[] b) {
        for (int i = 0; i != res.length; i++) {
            res[i] = (byte) (a[i] ^ b[i]);
        }
        this.engine.processBlock(res, 0, res, 0);
    }

    private void increment(byte[] val) {
        for (int i = val.length - 1; i >= 0; i--) {
            byte b = (byte) (val[i] + 1);
            val[i] = b;
            if (b != 0) {
                return;
            }
        }
    }

    private static boolean isTooLarge(byte[] bytes, int maxBytes) {
        return bytes != null && bytes.length > maxBytes;
    }
}
