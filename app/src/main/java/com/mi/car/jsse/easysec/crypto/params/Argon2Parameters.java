package com.mi.car.jsse.easysec.crypto.params;

import com.mi.car.jsse.easysec.crypto.CharToByteConverter;
import com.mi.car.jsse.easysec.crypto.PasswordConverter;
import com.mi.car.jsse.easysec.util.Arrays;

public class Argon2Parameters {
    public static final int ARGON2_VERSION_10 = 16;
    public static final int ARGON2_VERSION_13 = 19;
    public static final int ARGON2_d = 0;
    public static final int ARGON2_i = 1;
    public static final int ARGON2_id = 2;
    private static final int DEFAULT_ITERATIONS = 3;
    private static final int DEFAULT_LANES = 1;
    private static final int DEFAULT_MEMORY_COST = 12;
    private static final int DEFAULT_TYPE = 1;
    private static final int DEFAULT_VERSION = 19;
    private final byte[] additional;
    private final CharToByteConverter converter;
    private final int iterations;
    private final int lanes;
    private final int memory;
    private final byte[] salt;
    private final byte[] secret;
    private final int type;
    private final int version;

    public static class Builder {
        private byte[] additional;
        private CharToByteConverter converter;
        private int iterations;
        private int lanes;
        private int memory;
        private byte[] salt;
        private byte[] secret;
        private final int type;
        private int version;

        public Builder() {
            this(1);
        }

        public Builder(int type2) {
            this.converter = PasswordConverter.UTF8;
            this.type = type2;
            this.lanes = 1;
            this.memory = 4096;
            this.iterations = 3;
            this.version = 19;
        }

        public Builder withParallelism(int parallelism) {
            this.lanes = parallelism;
            return this;
        }

        public Builder withSalt(byte[] salt2) {
            this.salt = Arrays.clone(salt2);
            return this;
        }

        public Builder withSecret(byte[] secret2) {
            this.secret = Arrays.clone(secret2);
            return this;
        }

        public Builder withAdditional(byte[] additional2) {
            this.additional = Arrays.clone(additional2);
            return this;
        }

        public Builder withIterations(int iterations2) {
            this.iterations = iterations2;
            return this;
        }

        public Builder withMemoryAsKB(int memory2) {
            this.memory = memory2;
            return this;
        }

        public Builder withMemoryPowOfTwo(int memory2) {
            this.memory = 1 << memory2;
            return this;
        }

        public Builder withVersion(int version2) {
            this.version = version2;
            return this;
        }

        public Builder withCharToByteConverter(CharToByteConverter converter2) {
            this.converter = converter2;
            return this;
        }

        public Argon2Parameters build() {
            return new Argon2Parameters(this.type, this.salt, this.secret, this.additional, this.iterations, this.memory, this.lanes, this.version, this.converter);
        }

        public void clear() {
            Arrays.clear(this.salt);
            Arrays.clear(this.secret);
            Arrays.clear(this.additional);
        }
    }

    private Argon2Parameters(int type2, byte[] salt2, byte[] secret2, byte[] additional2, int iterations2, int memory2, int lanes2, int version2, CharToByteConverter converter2) {
        this.salt = Arrays.clone(salt2);
        this.secret = Arrays.clone(secret2);
        this.additional = Arrays.clone(additional2);
        this.iterations = iterations2;
        this.memory = memory2;
        this.lanes = lanes2;
        this.version = version2;
        this.type = type2;
        this.converter = converter2;
    }

    public byte[] getSalt() {
        return Arrays.clone(this.salt);
    }

    public byte[] getSecret() {
        return Arrays.clone(this.secret);
    }

    public byte[] getAdditional() {
        return Arrays.clone(this.additional);
    }

    public int getIterations() {
        return this.iterations;
    }

    public int getMemory() {
        return this.memory;
    }

    public int getLanes() {
        return this.lanes;
    }

    public int getVersion() {
        return this.version;
    }

    public int getType() {
        return this.type;
    }

    public CharToByteConverter getCharToByteConverter() {
        return this.converter;
    }

    public void clear() {
        Arrays.clear(this.salt);
        Arrays.clear(this.secret);
        Arrays.clear(this.additional);
    }
}
