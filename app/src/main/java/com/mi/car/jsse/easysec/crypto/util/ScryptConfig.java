package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.misc.MiscObjectIdentifiers;

public class ScryptConfig extends PBKDFConfig {
    private final int blockSize;
    private final int costParameter;
    private final int parallelizationParameter;
    private final int saltLength;

    public static class Builder {
        private final int blockSize;
        private final int costParameter;
        private final int parallelizationParameter;
        private int saltLength = 16;

        public Builder(int costParameter2, int blockSize2, int parallelizationParameter2) {
            if (costParameter2 <= 1 || !isPowerOf2(costParameter2)) {
                throw new IllegalArgumentException("Cost parameter N must be > 1 and a power of 2");
            }
            this.costParameter = costParameter2;
            this.blockSize = blockSize2;
            this.parallelizationParameter = parallelizationParameter2;
        }

        public Builder withSaltLength(int saltLength2) {
            this.saltLength = saltLength2;
            return this;
        }

        public ScryptConfig build() {
            return new ScryptConfig(this);
        }

        private static boolean isPowerOf2(int x) {
            return ((x + -1) & x) == 0;
        }
    }

    private ScryptConfig(Builder builder) {
        super(MiscObjectIdentifiers.id_scrypt);
        this.costParameter = builder.costParameter;
        this.blockSize = builder.blockSize;
        this.parallelizationParameter = builder.parallelizationParameter;
        this.saltLength = builder.saltLength;
    }

    public int getCostParameter() {
        return this.costParameter;
    }

    public int getBlockSize() {
        return this.blockSize;
    }

    public int getParallelizationParameter() {
        return this.parallelizationParameter;
    }

    public int getSaltLength() {
        return this.saltLength;
    }
}
