package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.util.Arrays;

public class DigestRandomGenerator implements RandomGenerator {
    private static long CYCLE_COUNT = 10L;
    private long stateCounter;
    private long seedCounter;
    private Digest digest;
    private byte[] state;
    private byte[] seed;

    public DigestRandomGenerator(Digest digest) {
        this.digest = digest;
        this.seed = new byte[digest.getDigestSize()];
        this.seedCounter = 1L;
        this.state = new byte[digest.getDigestSize()];
        this.stateCounter = 1L;
    }

    public void addSeedMaterial(byte[] inSeed) {
        synchronized(this) {
            if (!Arrays.isNullOrEmpty(inSeed)) {
                this.digestUpdate(inSeed);
            }

            this.digestUpdate(this.seed);
            this.digestDoFinal(this.seed);
        }
    }

    public void addSeedMaterial(long rSeed) {
        synchronized(this) {
            this.digestAddCounter(rSeed);
            this.digestUpdate(this.seed);
            this.digestDoFinal(this.seed);
        }
    }

    public void nextBytes(byte[] bytes) {
        this.nextBytes(bytes, 0, bytes.length);
    }

    public void nextBytes(byte[] bytes, int start, int len) {
        synchronized(this) {
            int stateOff = 0;
            this.generateState();
            int end = start + len;

            for(int i = start; i != end; ++i) {
                if (stateOff == this.state.length) {
                    this.generateState();
                    stateOff = 0;
                }

                bytes[i] = this.state[stateOff++];
            }

        }
    }

    private void cycleSeed() {
        this.digestUpdate(this.seed);
        this.digestAddCounter((long)(this.seedCounter++));
        this.digestDoFinal(this.seed);
    }

    private void generateState() {
        this.digestAddCounter((long)(this.stateCounter++));
        this.digestUpdate(this.state);
        this.digestUpdate(this.seed);
        this.digestDoFinal(this.state);
        if (this.stateCounter % CYCLE_COUNT == 0L) {
            this.cycleSeed();
        }

    }

    private void digestAddCounter(long seed) {
        for(int i = 0; i != 8; ++i) {
            this.digest.update((byte)((int)seed));
            seed >>>= 8;
        }

    }

    private void digestUpdate(byte[] inSeed) {
        this.digest.update(inSeed, 0, inSeed.length);
    }

    private void digestDoFinal(byte[] result) {
        this.digest.doFinal(result, 0);
    }
}
