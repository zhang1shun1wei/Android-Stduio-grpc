package com.mi.car.jsse.easysec.crypto.prng;

public class ReversedWindowGenerator implements RandomGenerator {
    private final RandomGenerator generator;
    private byte[] window;
    private int windowCount;

    public ReversedWindowGenerator(RandomGenerator generator, int windowSize) {
        if (generator == null) {
            throw new IllegalArgumentException("generator cannot be null");
        } else if (windowSize < 2) {
            throw new IllegalArgumentException("windowSize must be at least 2");
        } else {
            this.generator = generator;
            this.window = new byte[windowSize];
        }
    }

    public void addSeedMaterial(byte[] seed) {
        synchronized(this) {
            this.windowCount = 0;
            this.generator.addSeedMaterial(seed);
        }
    }

    public void addSeedMaterial(long seed) {
        synchronized(this) {
            this.windowCount = 0;
            this.generator.addSeedMaterial(seed);
        }
    }

    public void nextBytes(byte[] bytes) {
        this.doNextBytes(bytes, 0, bytes.length);
    }

    public void nextBytes(byte[] bytes, int start, int len) {
        this.doNextBytes(bytes, start, len);
    }

    private void doNextBytes(byte[] bytes, int start, int len) {
        synchronized(this) {
            for(int done = 0; done < len; bytes[start + done++] = this.window[--this.windowCount]) {
                if (this.windowCount < 1) {
                    this.generator.nextBytes(this.window, 0, this.window.length);
                    this.windowCount = this.window.length;
                }
            }

        }
    }
}
