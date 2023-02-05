package com.mi.car.jsse.easysec.crypto.generators;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.digests.Blake2bDigest;
import com.mi.car.jsse.easysec.crypto.params.Argon2Parameters;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Longs;
import com.mi.car.jsse.easysec.util.Pack;

public class Argon2BytesGenerator {
    private static final int ARGON2_ADDRESSES_IN_BLOCK = 128;
    private static final int ARGON2_BLOCK_SIZE = 1024;
    private static final int ARGON2_PREHASH_DIGEST_LENGTH = 64;
    private static final int ARGON2_PREHASH_SEED_LENGTH = 72;
    private static final int ARGON2_QWORDS_IN_BLOCK = 128;
    private static final int ARGON2_SYNC_POINTS = 4;
    private static final long M32L = 4294967295L;
    private static final int MAX_PARALLELISM = 16777216;
    private static final int MIN_ITERATIONS = 1;
    private static final int MIN_OUTLEN = 4;
    private static final int MIN_PARALLELISM = 1;
    private static final byte[] ZERO_BYTES = new byte[4];
    private int laneLength;
    private Block[] memory;
    private Argon2Parameters parameters;
    private int segmentLength;

    public void init(Argon2Parameters parameters2) {
        this.parameters = parameters2;
        if (parameters2.getLanes() < 1) {
            throw new IllegalStateException("lanes must be greater than 1");
        } else if (parameters2.getLanes() > MAX_PARALLELISM) {
            throw new IllegalStateException("lanes must be less than 16777216");
        } else if (parameters2.getMemory() < parameters2.getLanes() * 2) {
            throw new IllegalStateException("memory is less than: " + (parameters2.getLanes() * 2) + " expected " + (parameters2.getLanes() * 2));
        } else if (parameters2.getIterations() < 1) {
            throw new IllegalStateException("iterations is less than: 1");
        } else {
            doInit(parameters2);
        }
    }

    public int generateBytes(char[] password, byte[] out) {
        return generateBytes(this.parameters.getCharToByteConverter().convert(password), out);
    }

    public int generateBytes(char[] password, byte[] out, int outOff, int outLen) {
        return generateBytes(this.parameters.getCharToByteConverter().convert(password), out, outOff, outLen);
    }

    public int generateBytes(byte[] password, byte[] out) {
        return generateBytes(password, out, 0, out.length);
    }

    public int generateBytes(byte[] password, byte[] out, int outOff, int outLen) {
        if (outLen < 4) {
            throw new IllegalStateException("output length less than 4");
        }
        byte[] tmpBlockBytes = new byte[1024];
        initialize(tmpBlockBytes, password, outLen);
        fillMemoryBlocks();
        digest(tmpBlockBytes, out, outOff, outLen);
        reset();
        return outLen;
    }

    private void reset() {
        if (this.memory != null) {
            for (int i = 0; i < this.memory.length; i++) {
                Block b = this.memory[i];
                if (b != null) {
                    b.clear();
                }
            }
        }
    }

    private void doInit(Argon2Parameters parameters2) {
        int memoryBlocks = parameters2.getMemory();
        if (memoryBlocks < parameters2.getLanes() * 8) {
            memoryBlocks = parameters2.getLanes() * 8;
        }
        this.segmentLength = memoryBlocks / (parameters2.getLanes() * 4);
        this.laneLength = this.segmentLength * 4;
        initMemory(this.segmentLength * parameters2.getLanes() * 4);
    }

    private void initMemory(int memoryBlocks) {
        this.memory = new Block[memoryBlocks];
        for (int i = 0; i < this.memory.length; i++) {
            this.memory[i] = new Block();
        }
    }

    private void fillMemoryBlocks() {
        FillBlock filler = new FillBlock();
        Position position = new Position();
        for (int pass = 0; pass < this.parameters.getIterations(); pass++) {
            position.pass = pass;
            for (int slice = 0; slice < 4; slice++) {
                position.slice = slice;
                for (int lane = 0; lane < this.parameters.getLanes(); lane++) {
                    position.lane = lane;
                    fillSegment(filler, position);
                }
            }
        }
    }

    private void fillSegment(FillBlock filler, Position position) {
        Block addressBlock = null;
        Block inputBlock = null;
        boolean dataIndependentAddressing = isDataIndependentAddressing(position);
        int startingIndex = getStartingIndex(position);
        int currentOffset = (position.lane * this.laneLength) + (position.slice * this.segmentLength) + startingIndex;
        int prevOffset = getPrevOffset(currentOffset);
        if (dataIndependentAddressing) {
            addressBlock = filler.addressBlock.clear();
            inputBlock = filler.inputBlock.clear();
            initAddressBlocks(filler, position, inputBlock, addressBlock);
        }
        boolean withXor = isWithXor(position);
        for (int index = startingIndex; index < this.segmentLength; index++) {
            long pseudoRandom = getPseudoRandom(filler, index, addressBlock, inputBlock, prevOffset, dataIndependentAddressing);
            int refLane = getRefLane(position, pseudoRandom);
            int refColumn = getRefColumn(position, index, pseudoRandom, refLane == position.lane);
            Block prevBlock = this.memory[prevOffset];
            Block refBlock = this.memory[(this.laneLength * refLane) + refColumn];
            Block currentBlock = this.memory[currentOffset];
            if (withXor) {
                filler.fillBlockWithXor(prevBlock, refBlock, currentBlock);
            } else {
                filler.fillBlock(prevBlock, refBlock, currentBlock);
            }
            prevOffset = currentOffset;
            currentOffset++;
        }
    }

    private boolean isDataIndependentAddressing(Position position) {
        if (this.parameters.getType() == 1) {
            return true;
        }
        if (this.parameters.getType() == 2 && position.pass == 0 && position.slice < 2) {
            return true;
        }
        return false;
    }

    private void initAddressBlocks(FillBlock filler, Position position, Block inputBlock, Block addressBlock) {
        inputBlock.v[0] = intToLong(position.pass);
        inputBlock.v[1] = intToLong(position.lane);
        inputBlock.v[2] = intToLong(position.slice);
        inputBlock.v[3] = intToLong(this.memory.length);
        inputBlock.v[4] = intToLong(this.parameters.getIterations());
        inputBlock.v[5] = intToLong(this.parameters.getType());
        if (position.pass == 0 && position.slice == 0) {
            nextAddresses(filler, inputBlock, addressBlock);
        }
    }

    private boolean isWithXor(Position position) {
        return (position.pass == 0 || this.parameters.getVersion() == 16) ? false : true;
    }

    private int getPrevOffset(int currentOffset) {
        if (currentOffset % this.laneLength == 0) {
            return (this.laneLength + currentOffset) - 1;
        }
        return currentOffset - 1;
    }

    private static int getStartingIndex(Position position) {
        if (position.pass == 0 && position.slice == 0) {
            return 2;
        }
        return 0;
    }

    private void nextAddresses(FillBlock filler, Block inputBlock, Block addressBlock) {
        long[] jArr = inputBlock.v;
        jArr[6] = jArr[6] + 1;
        filler.fillBlock(inputBlock, addressBlock);
        filler.fillBlock(addressBlock, addressBlock);
    }

    private long getPseudoRandom(FillBlock filler, int index, Block addressBlock, Block inputBlock, int prevOffset, boolean dataIndependentAddressing) {
        if (!dataIndependentAddressing) {
            return this.memory[prevOffset].v[0];
        }
        int addressIndex = index % 128;
        if (addressIndex == 0) {
            nextAddresses(filler, inputBlock, addressBlock);
        }
        return addressBlock.v[addressIndex];
    }

    private int getRefLane(Position position, long pseudoRandom) {
        int refLane = (int) ((pseudoRandom >>> 32) % ((long) this.parameters.getLanes()));
        if (position.pass == 0 && position.slice == 0) {
            return position.lane;
        }
        return refLane;
    }

    private int getRefColumn(Position position, int index, long pseudoRandom, boolean sameLane) {
        int startPosition;
        int referenceAreaSize;
        int i = -1;
        if (position.pass == 0) {
            startPosition = 0;
            if (sameLane) {
                referenceAreaSize = ((position.slice * this.segmentLength) + index) - 1;
            } else {
                int i2 = position.slice * this.segmentLength;
                if (index != 0) {
                    i = 0;
                }
                referenceAreaSize = i2 + i;
            }
        } else {
            startPosition = ((position.slice + 1) * this.segmentLength) % this.laneLength;
            if (sameLane) {
                referenceAreaSize = ((this.laneLength - this.segmentLength) + index) - 1;
            } else {
                int i3 = this.laneLength - this.segmentLength;
                if (index != 0) {
                    i = 0;
                }
                referenceAreaSize = i3 + i;
            }
        }
        long relativePosition = pseudoRandom & M32L;
        return ((int) (((long) startPosition) + (((long) (referenceAreaSize - 1)) - ((((long) referenceAreaSize) * ((relativePosition * relativePosition) >>> 32)) >>> 32)))) % this.laneLength;
    }

    private void digest(byte[] tmpBlockBytes, byte[] out, int outOff, int outLen) {
        Block finalBlock = this.memory[this.laneLength - 1];
        for (int i = 1; i < this.parameters.getLanes(); i++) {
            finalBlock.xorWith(this.memory[(this.laneLength * i) + (this.laneLength - 1)]);
        }
        finalBlock.toBytes(tmpBlockBytes);
        hash(tmpBlockBytes, out, outOff, outLen);
    }

    private void hash(byte[] input, byte[] out, int outOff, int outLen) {
        byte[] outLenBytes = new byte[4];
        Pack.intToLittleEndian(outLen, outLenBytes, 0);
        if (outLen <= 64) {
            Blake2bDigest blake = new Blake2bDigest(outLen * 8);
            blake.update(outLenBytes, 0, outLenBytes.length);
            blake.update(input, 0, input.length);
            blake.doFinal(out, outOff);
            return;
        }
        Blake2bDigest digest = new Blake2bDigest(512);
        byte[] outBuffer = new byte[64];
        digest.update(outLenBytes, 0, outLenBytes.length);
        digest.update(input, 0, input.length);
        digest.doFinal(outBuffer, 0);
        int halfLen = 64 / 2;
        System.arraycopy(outBuffer, 0, out, outOff, halfLen);
        int outPos = outOff + 32;
        int r = ((outLen + 31) / 32) - 2;
        int i = 2;
        while (i <= r) {
            digest.update(outBuffer, 0, outBuffer.length);
            digest.doFinal(outBuffer, 0);
            System.arraycopy(outBuffer, 0, out, outPos, halfLen);
            i++;
            outPos += 32;
        }
        Blake2bDigest digest2 = new Blake2bDigest((outLen - (r * 32)) * 8);
        digest2.update(outBuffer, 0, outBuffer.length);
        digest2.doFinal(out, outPos);
    }

    /* access modifiers changed from: private */
    public static void roundFunction(Block block, int v0, int v1, int v2, int v3, int v4, int v5, int v6, int v7, int v8, int v9, int v10, int v11, int v12, int v13, int v14, int v15) {
        long[] v = block.v;
        F(v, v0, v4, v8, v12);
        F(v, v1, v5, v9, v13);
        F(v, v2, v6, v10, v14);
        F(v, v3, v7, v11, v15);
        F(v, v0, v5, v10, v15);
        F(v, v1, v6, v11, v12);
        F(v, v2, v7, v8, v13);
        F(v, v3, v4, v9, v14);
    }

    private static void F(long[] v, int a, int b, int c, int d) {
        quarterRound(v, a, b, d, 32);
        quarterRound(v, c, d, b, 24);
        quarterRound(v, a, b, d, 16);
        quarterRound(v, c, d, b, 63);
    }

    private static void quarterRound(long[] v, int x, int y, int z, int s) {
        long a = v[x];
        long b = v[y];
        long c = v[z];
        long a2 = a + (2 * (M32L & a) * (M32L & b)) + b;
        long c2 = Longs.rotateRight(c ^ a2, s);
        v[x] = a2;
        v[z] = c2;
    }

    private void initialize(byte[] tmpBlockBytes, byte[] password, int outputLength) {
        Blake2bDigest blake = new Blake2bDigest(512);
        int[] values = {this.parameters.getLanes(), outputLength, this.parameters.getMemory(), this.parameters.getIterations(), this.parameters.getVersion(), this.parameters.getType()};
        Pack.intToLittleEndian(values, tmpBlockBytes, 0);
        blake.update(tmpBlockBytes, 0, values.length * 4);
        addByteString(tmpBlockBytes, blake, password);
        addByteString(tmpBlockBytes, blake, this.parameters.getSalt());
        addByteString(tmpBlockBytes, blake, this.parameters.getSecret());
        addByteString(tmpBlockBytes, blake, this.parameters.getAdditional());
        byte[] initialHashWithZeros = new byte[ARGON2_PREHASH_SEED_LENGTH];
        blake.doFinal(initialHashWithZeros, 0);
        fillFirstBlocks(tmpBlockBytes, initialHashWithZeros);
    }

    private static void addByteString(byte[] tmpBlockBytes, Digest digest, byte[] octets) {
        if (octets == null) {
            digest.update(ZERO_BYTES, 0, 4);
            return;
        }
        Pack.intToLittleEndian(octets.length, tmpBlockBytes, 0);
        digest.update(tmpBlockBytes, 0, 4);
        digest.update(octets, 0, octets.length);
    }

    private void fillFirstBlocks(byte[] tmpBlockBytes, byte[] initialHashWithZeros) {
        byte[] initialHashWithOnes = new byte[ARGON2_PREHASH_SEED_LENGTH];
        System.arraycopy(initialHashWithZeros, 0, initialHashWithOnes, 0, 64);
        initialHashWithOnes[64] = 1;
        for (int i = 0; i < this.parameters.getLanes(); i++) {
            Pack.intToLittleEndian(i, initialHashWithZeros, 68);
            Pack.intToLittleEndian(i, initialHashWithOnes, 68);
            hash(initialHashWithZeros, tmpBlockBytes, 0, 1024);
            this.memory[(this.laneLength * i) + 0].fromBytes(tmpBlockBytes);
            hash(initialHashWithOnes, tmpBlockBytes, 0, 1024);
            this.memory[(this.laneLength * i) + 1].fromBytes(tmpBlockBytes);
        }
    }

    private long intToLong(int x) {
        return ((long) x) & M32L;
    }

    /* access modifiers changed from: private */
    public static class FillBlock {
        Block R;
        Block Z;
        Block addressBlock;
        Block inputBlock;

        private FillBlock() {
            this.R = new Block();
            this.Z = new Block();
            this.addressBlock = new Block();
            this.inputBlock = new Block();
        }

        private void applyBlake() {
            for (int i = 0; i < 8; i++) {
                int i16 = i * 16;
                Argon2BytesGenerator.roundFunction(this.Z, i16, i16 + 1, i16 + 2, i16 + 3, i16 + 4, i16 + 5, i16 + 6, i16 + 7, i16 + 8, i16 + 9, i16 + 10, i16 + 11, i16 + 12, i16 + 13, i16 + 14, i16 + 15);
            }
            for (int i2 = 0; i2 < 8; i2++) {
                int i22 = i2 * 2;
                Argon2BytesGenerator.roundFunction(this.Z, i22, i22 + 1, i22 + 16, i22 + 17, i22 + 32, i22 + 33, i22 + 48, i22 + 49, i22 + 64, i22 + 65, i22 + 80, i22 + 81, i22 + 96, i22 + 97, i22 + 112, i22 + 113);
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void fillBlock(Block Y, Block currentBlock) {
            this.Z.copyBlock(Y);
            applyBlake();
            currentBlock.xor(Y, this.Z);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void fillBlock(Block X, Block Y, Block currentBlock) {
            this.R.xor(X, Y);
            this.Z.copyBlock(this.R);
            applyBlake();
            currentBlock.xor(this.R, this.Z);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void fillBlockWithXor(Block X, Block Y, Block currentBlock) {
            this.R.xor(X, Y);
            this.Z.copyBlock(this.R);
            applyBlake();
            currentBlock.xorWith(this.R, this.Z);
        }
    }

    /* access modifiers changed from: private */
    public static class Block {
        private static final int SIZE = 128;
        private final long[] v;

        private Block() {
            this.v = new long[128];
        }

        /* access modifiers changed from: package-private */
        public void fromBytes(byte[] input) {
            if (input.length < 1024) {
                throw new IllegalArgumentException("input shorter than blocksize");
            }
            Pack.littleEndianToLong(input, 0, this.v);
        }

        /* access modifiers changed from: package-private */
        public void toBytes(byte[] output) {
            if (output.length < 1024) {
                throw new IllegalArgumentException("output shorter than blocksize");
            }
            Pack.longToLittleEndian(this.v, output, 0);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void copyBlock(Block other) {
            System.arraycopy(other.v, 0, this.v, 0, 128);
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void xor(Block b1, Block b2) {
            long[] v0 = this.v;
            long[] v1 = b1.v;
            long[] v2 = b2.v;
            for (int i = 0; i < 128; i++) {
                v0[i] = v1[i] ^ v2[i];
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void xorWith(Block b1) {
            long[] v0 = this.v;
            long[] v1 = b1.v;
            for (int i = 0; i < 128; i++) {
                v0[i] = v0[i] ^ v1[i];
            }
        }

        /* access modifiers changed from: private */
        /* access modifiers changed from: public */
        private void xorWith(Block b1, Block b2) {
            long[] v0 = this.v;
            long[] v1 = b1.v;
            long[] v2 = b2.v;
            for (int i = 0; i < 128; i++) {
                v0[i] = v0[i] ^ (v1[i] ^ v2[i]);
            }
        }

        public Block clear() {
            Arrays.fill(this.v, 0);
            return this;
        }
    }

    /* access modifiers changed from: private */
    public static class Position {
        int lane;
        int pass;
        int slice;

        Position() {
        }
    }
}
