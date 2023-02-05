package com.mi.car.jsse.easysec.crypto.prng;

import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;

public class ThreadedSeedGenerator {

    private class SeedGenerator implements Runnable {
        private volatile int counter;
        private volatile boolean stop;

        private SeedGenerator() {
            this.counter = 0;
            this.stop = false;
        }

        public void run() {
            while (!this.stop) {
                this.counter++;
            }
        }

        public byte[] generateSeed(int numbytes, boolean fast) {
            int end;
            Thread t = new Thread(this);
            byte[] result = new byte[numbytes];
            this.counter = 0;
            this.stop = false;
            int last = 0;
            t.start();
            if (fast) {
                end = numbytes;
            } else {
                end = numbytes * 8;
            }
            for (int i = 0; i < end; i++) {
                while (this.counter == last) {
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                    }
                }
                last = this.counter;
                if (fast) {
                    result[i] = (byte) (last & GF2Field.MASK);
                } else {
                    int bytepos = i / 8;
                    result[bytepos] = (byte) ((result[bytepos] << 1) | (last & 1));
                }
            }
            this.stop = true;
            return result;
        }
    }

    public byte[] generateSeed(int numBytes, boolean fast) {
        return new SeedGenerator().generateSeed(numBytes, fast);
    }
}
