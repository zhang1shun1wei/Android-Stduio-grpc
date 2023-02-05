package com.mi.car.jsse.easysec.crypto.digests;

import com.mi.car.jsse.easysec.crypto.ExtendedDigest;
import com.mi.car.jsse.easysec.crypto.Xof;
import com.mi.car.jsse.easysec.crypto.params.Blake3Parameters;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.Memoable;
import com.mi.car.jsse.easysec.util.Pack;
import java.util.Iterator;
import java.util.Stack;

public class Blake3Digest implements ExtendedDigest, Memoable, Xof {
    private static final int BLOCKLEN = 64;
    private static final int CHAINING0 = 0;
    private static final int CHAINING1 = 1;
    private static final int CHAINING2 = 2;
    private static final int CHAINING3 = 3;
    private static final int CHAINING4 = 4;
    private static final int CHAINING5 = 5;
    private static final int CHAINING6 = 6;
    private static final int CHAINING7 = 7;
    private static final int CHUNKEND = 2;
    private static final int CHUNKLEN = 1024;
    private static final int CHUNKSTART = 1;
    private static final int COUNT0 = 12;
    private static final int COUNT1 = 13;
    private static final int DATALEN = 14;
    private static final int DERIVECONTEXT = 32;
    private static final int DERIVEKEY = 64;
    private static final String ERR_OUTPUTTING = "Already outputting";
    private static final int FLAGS = 15;
    private static final int[] IV = {1779033703, -1150833019, 1013904242, -1521486534, 1359893119, -1694144372, 528734635, 1541459225};
    private static final int IV0 = 8;
    private static final int IV1 = 9;
    private static final int IV2 = 10;
    private static final int IV3 = 11;
    private static final int KEYEDHASH = 16;
    private static final int NUMWORDS = 8;
    private static final int PARENT = 4;
    private static final int ROOT = 8;
    private static final byte[] ROTATE = {Tnaf.POW_2_WIDTH, 12, 8, 7};
    private static final int ROUNDS = 7;
    private static final byte[] SIGMA = {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8};
    private long outputAvailable;
    private boolean outputting;
    private final byte[] theBuffer;
    private final int[] theChaining;
    private long theCounter;
    private int theCurrBytes;
    private final int theDigestLen;
    private final byte[] theIndices;
    private final int[] theK;
    private final int[] theM;
    private int theMode;
    private int theOutputDataLen;
    private int theOutputMode;
    private int thePos;
    private final Stack theStack;
    private final int[] theV;

    public Blake3Digest() {
        this(32);
    }

    public Blake3Digest(int pDigestLen) {
        this.theBuffer = new byte[64];
        this.theK = new int[8];
        this.theChaining = new int[8];
        this.theV = new int[16];
        this.theM = new int[16];
        this.theIndices = new byte[16];
        this.theStack = new Stack();
        this.theDigestLen = pDigestLen;
        init(null);
    }

    public Blake3Digest(Blake3Digest pSource) {
        this.theBuffer = new byte[64];
        this.theK = new int[8];
        this.theChaining = new int[8];
        this.theV = new int[16];
        this.theM = new int[16];
        this.theIndices = new byte[16];
        this.theStack = new Stack();
        this.theDigestLen = pSource.theDigestLen;
        reset(pSource);
    }

    @Override // com.mi.car.jsse.easysec.crypto.ExtendedDigest
    public int getByteLength() {
        return 64;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public String getAlgorithmName() {
        return "BLAKE3";
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int getDigestSize() {
        return this.theDigestLen;
    }

    public void init(Blake3Parameters pParams) {
        byte[] myContext = null;
        byte[] myKey = pParams == null ? null : pParams.getKey();
        if (pParams != null) {
            myContext = pParams.getContext();
        }
        reset();
        if (myKey != null) {
            initKey(myKey);
            Arrays.fill(myKey, (byte) 0);
        } else if (myContext != null) {
            initNullKey();
            this.theMode = 32;
            update(myContext, 0, myContext.length);
            doFinal(this.theBuffer, 0);
            initKeyFromContext();
            reset();
        } else {
            initNullKey();
            this.theMode = 0;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte b) {
        if (this.outputting) {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }
        if (this.theBuffer.length - this.thePos == 0) {
            compressBlock(this.theBuffer, 0);
            Arrays.fill(this.theBuffer, (byte) 0);
            this.thePos = 0;
        }
        this.theBuffer[this.thePos] = b;
        this.thePos++;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void update(byte[] pMessage, int pOffset, int pLen) {
        if (pMessage != null && pLen != 0) {
            if (this.outputting) {
                throw new IllegalStateException(ERR_OUTPUTTING);
            }
            int remainingLen = 0;
            if (this.thePos != 0) {
                remainingLen = 64 - this.thePos;
                if (remainingLen >= pLen) {
                    System.arraycopy(pMessage, pOffset, this.theBuffer, this.thePos, pLen);
                    this.thePos += pLen;
                    return;
                }
                System.arraycopy(pMessage, pOffset, this.theBuffer, this.thePos, remainingLen);
                compressBlock(this.theBuffer, 0);
                this.thePos = 0;
                Arrays.fill(this.theBuffer, (byte) 0);
            }
            int blockWiseLastPos = (pOffset + pLen) - 64;
            int messagePos = pOffset + remainingLen;
            while (messagePos < blockWiseLastPos) {
                compressBlock(pMessage, messagePos);
                messagePos += 64;
            }
            int len = pLen - messagePos;
            System.arraycopy(pMessage, messagePos, this.theBuffer, 0, pOffset + len);
            this.thePos += pOffset + len;
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public int doFinal(byte[] pOutput, int pOutOffset) {
        return doFinal(pOutput, pOutOffset, getDigestSize());
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doFinal(byte[] pOut, int pOutOffset, int pOutLen) {
        if (this.outputting) {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }
        int length = doOutput(pOut, pOutOffset, pOutLen);
        reset();
        return length;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Xof
    public int doOutput(byte[] pOut, int pOutOffset, int pOutLen) {
        if (!this.outputting) {
            compressFinalBlock(this.thePos);
        }
        if (pOutLen < 0 || (this.outputAvailable >= 0 && ((long) pOutLen) > this.outputAvailable)) {
            throw new IllegalArgumentException("Insufficient bytes remaining");
        }
        int dataLeft = pOutLen;
        int outPos = pOutOffset;
        if (this.thePos < 64) {
            int dataToCopy = Math.min(dataLeft, 64 - this.thePos);
            System.arraycopy(this.theBuffer, this.thePos, pOut, outPos, dataToCopy);
            this.thePos += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }
        while (dataLeft > 0) {
            nextOutputBlock();
            int dataToCopy2 = Math.min(dataLeft, 64);
            System.arraycopy(this.theBuffer, 0, pOut, outPos, dataToCopy2);
            this.thePos += dataToCopy2;
            outPos += dataToCopy2;
            dataLeft -= dataToCopy2;
        }
        this.outputAvailable -= (long) pOutLen;
        return pOutLen;
    }

    @Override // com.mi.car.jsse.easysec.crypto.Digest
    public void reset() {
        resetBlockCount();
        this.thePos = 0;
        this.outputting = false;
        Arrays.fill(this.theBuffer, (byte) 0);
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public void reset(Memoable pSource) {
        Blake3Digest mySource = (Blake3Digest) pSource;
        this.theCounter = mySource.theCounter;
        this.theCurrBytes = mySource.theCurrBytes;
        this.theMode = mySource.theMode;
        this.outputting = mySource.outputting;
        this.outputAvailable = mySource.outputAvailable;
        this.theOutputMode = mySource.theOutputMode;
        this.theOutputDataLen = mySource.theOutputDataLen;
        System.arraycopy(mySource.theChaining, 0, this.theChaining, 0, this.theChaining.length);
        System.arraycopy(mySource.theK, 0, this.theK, 0, this.theK.length);
        System.arraycopy(mySource.theM, 0, this.theM, 0, this.theM.length);
        this.theStack.clear();
        Iterator it = mySource.theStack.iterator();
        while (it.hasNext()) {
            this.theStack.push(Arrays.clone((int[]) it.next()));
        }
        System.arraycopy(mySource.theBuffer, 0, this.theBuffer, 0, this.theBuffer.length);
        this.thePos = mySource.thePos;
    }

    @Override // com.mi.car.jsse.easysec.util.Memoable
    public Memoable copy() {
        return new Blake3Digest(this);
    }

    private void compressBlock(byte[] pMessage, int pMsgPos) {
        initChunkBlock(64, false);
        initM(pMessage, pMsgPos);
        compress();
        if (this.theCurrBytes == 0) {
            adjustStack();
        }
    }

    private void adjustStack() {
        long myCount = this.theCounter;
        while (myCount > 0 && (myCount & 1) != 1) {
            System.arraycopy((int[]) this.theStack.pop(), 0, this.theM, 0, 8);
            System.arraycopy(this.theChaining, 0, this.theM, 8, 8);
            initParentBlock();
            compress();
            myCount >>= 1;
        }
        this.theStack.push(Arrays.copyOf(this.theChaining, 8));
    }

    private void compressFinalBlock(int pDataLen) {
        initChunkBlock(pDataLen, true);
        initM(this.theBuffer, 0);
        compress();
        processStack();
    }

    private void processStack() {
        while (!this.theStack.isEmpty()) {
            System.arraycopy((int[]) this.theStack.pop(), 0, this.theM, 0, 8);
            System.arraycopy(this.theChaining, 0, this.theM, 8, 8);
            initParentBlock();
            if (this.theStack.isEmpty()) {
                setRoot();
            }
            compress();
        }
    }

    private void compress() {
        initIndices();
        for (int round = 0; round < 6; round++) {
            performRound();
            permuteIndices();
        }
        performRound();
        adjustChaining();
    }

    private void performRound() {
        int idx = 0 + 1;
        mixG(0, 0, 4, 8, 12);
        int idx2 = idx + 1;
        mixG(idx, 1, 5, 9, 13);
        int idx3 = idx2 + 1;
        mixG(idx2, 2, 6, 10, 14);
        int idx4 = idx3 + 1;
        mixG(idx3, 3, 7, 11, 15);
        int idx5 = idx4 + 1;
        mixG(idx4, 0, 5, 10, 15);
        int idx6 = idx5 + 1;
        mixG(idx5, 1, 6, 11, 12);
        mixG(idx6, 2, 7, 8, 13);
        mixG(idx6 + 1, 3, 4, 9, 14);
    }

    private void initM(byte[] pMessage, int pMsgPos) {
        for (int i = 0; i < 16; i++) {
            this.theM[i] = Pack.littleEndianToInt(pMessage, (i * 4) + pMsgPos);
        }
    }

    private void adjustChaining() {
        if (this.outputting) {
            for (int i = 0; i < 8; i++) {
                int[] iArr = this.theV;
                iArr[i] = iArr[i] ^ this.theV[i + 8];
                int[] iArr2 = this.theV;
                int i2 = i + 8;
                iArr2[i2] = iArr2[i2] ^ this.theChaining[i];
            }
            for (int i3 = 0; i3 < 16; i3++) {
                Pack.intToLittleEndian(this.theV[i3], this.theBuffer, i3 * 4);
            }
            this.thePos = 0;
            return;
        }
        for (int i4 = 0; i4 < 8; i4++) {
            this.theChaining[i4] = this.theV[i4] ^ this.theV[i4 + 8];
        }
    }

    private void mixG(int msgIdx, int posA, int posB, int posC, int posD) {
        int msg = msgIdx << 1;
        int[] iArr = this.theV;
        iArr[posA] = iArr[posA] + this.theV[posB] + this.theM[this.theIndices[msg]];
        int rot = 0 + 1;
        this.theV[posD] = Integers.rotateRight(this.theV[posD] ^ this.theV[posA], ROTATE[0]);
        int[] iArr2 = this.theV;
        iArr2[posC] = iArr2[posC] + this.theV[posD];
        int rot2 = rot + 1;
        this.theV[posB] = Integers.rotateRight(this.theV[posB] ^ this.theV[posC], ROTATE[rot]);
        int[] iArr3 = this.theV;
        iArr3[posA] = iArr3[posA] + this.theV[posB] + this.theM[this.theIndices[msg + 1]];
        this.theV[posD] = Integers.rotateRight(this.theV[posD] ^ this.theV[posA], ROTATE[rot2]);
        int[] iArr4 = this.theV;
        iArr4[posC] = iArr4[posC] + this.theV[posD];
        this.theV[posB] = Integers.rotateRight(this.theV[posB] ^ this.theV[posC], ROTATE[rot2 + 1]);
    }

    private void initIndices() {
        for (byte i = 0; i < this.theIndices.length; i = (byte) (i + 1)) {
            this.theIndices[i] = i;
        }
    }

    private void permuteIndices() {
        for (byte i = 0; i < this.theIndices.length; i = (byte) (i + 1)) {
            this.theIndices[i] = SIGMA[this.theIndices[i]];
        }
    }

    private void initNullKey() {
        System.arraycopy(IV, 0, this.theK, 0, 8);
    }

    private void initKey(byte[] pKey) {
        for (int i = 0; i < 8; i++) {
            this.theK[i] = Pack.littleEndianToInt(pKey, i * 4);
        }
        this.theMode = 16;
    }

    private void initKeyFromContext() {
        System.arraycopy(this.theV, 0, this.theK, 0, 8);
        this.theMode = 64;
    }

    private void initChunkBlock(int pDataLen, boolean pFinal) {
        int i;
        System.arraycopy(this.theCurrBytes == 0 ? this.theK : this.theChaining, 0, this.theV, 0, 8);
        System.arraycopy(IV, 0, this.theV, 8, 4);
        this.theV[12] = (int) this.theCounter;
        this.theV[13] = (int) (this.theCounter >> 32);
        this.theV[14] = pDataLen;
        int[] iArr = this.theV;
        int i2 = this.theMode;
        if (this.theCurrBytes == 0) {
            i = 1;
        } else {
            i = 0;
        }
        iArr[15] = (pFinal ? 2 : 0) + i2 + i;
        this.theCurrBytes += pDataLen;
        if (this.theCurrBytes >= 1024) {
            incrementBlockCount();
            int[] iArr2 = this.theV;
            iArr2[15] = iArr2[15] | 2;
        }
        if (pFinal && this.theStack.isEmpty()) {
            setRoot();
        }
    }

    private void initParentBlock() {
        System.arraycopy(this.theK, 0, this.theV, 0, 8);
        System.arraycopy(IV, 0, this.theV, 8, 4);
        this.theV[12] = 0;
        this.theV[13] = 0;
        this.theV[14] = 64;
        this.theV[15] = this.theMode | 4;
    }

    private void nextOutputBlock() {
        this.theCounter++;
        System.arraycopy(this.theChaining, 0, this.theV, 0, 8);
        System.arraycopy(IV, 0, this.theV, 8, 4);
        this.theV[12] = (int) this.theCounter;
        this.theV[13] = (int) (this.theCounter >> 32);
        this.theV[14] = this.theOutputDataLen;
        this.theV[15] = this.theOutputMode;
        compress();
    }

    private void incrementBlockCount() {
        this.theCounter++;
        this.theCurrBytes = 0;
    }

    private void resetBlockCount() {
        this.theCounter = 0;
        this.theCurrBytes = 0;
    }

    private void setRoot() {
        int[] iArr = this.theV;
        iArr[15] = iArr[15] | 8;
        this.theOutputMode = this.theV[15];
        this.theOutputDataLen = this.theV[14];
        this.theCounter = 0;
        this.outputting = true;
        this.outputAvailable = -1;
        System.arraycopy(this.theV, 0, this.theChaining, 0, 8);
    }
}
