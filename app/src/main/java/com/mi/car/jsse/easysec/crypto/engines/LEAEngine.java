package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.util.Pack;
import java.lang.reflect.Array;

public class LEAEngine implements BlockCipher {
    private static final int BASEROUNDS = 16;
    private static final int BLOCKSIZE = 16;
    private static final int[] DELTA = {-1007687205, 1147300610, 2044886154, 2027892972, 1902027934, -947529206, -531697110, -440137385};
    private static final int KEY0 = 0;
    private static final int KEY1 = 1;
    private static final int KEY2 = 2;
    private static final int KEY3 = 3;
    private static final int KEY4 = 4;
    private static final int KEY5 = 5;
    private static final int MASK128 = 3;
    private static final int MASK256 = 7;
    private static final int NUMWORDS = 4;
    private static final int NUMWORDS128 = 4;
    private static final int NUMWORDS192 = 6;
    private static final int NUMWORDS256 = 8;
    private static final int ROT1 = 1;
    private static final int ROT11 = 11;
    private static final int ROT13 = 13;
    private static final int ROT17 = 17;
    private static final int ROT3 = 3;
    private static final int ROT5 = 5;
    private static final int ROT6 = 6;
    private static final int ROT9 = 9;
    private boolean forEncryption;
    private final int[] theBlock = new int[4];
    private int[][] theRoundKeys;
    private int theRounds;

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean pEncrypt, CipherParameters pParams) {
        if (!(pParams instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to LEA init - " + pParams.getClass().getName());
        }
        byte[] myKey = ((KeyParameter) pParams).getKey();
        int myKeyLen = myKey.length;
        if ((myKeyLen << 1) % 16 != 0 || myKeyLen < 16 || myKeyLen > 32) {
            throw new IllegalArgumentException("KeyBitSize must be 128, 192 or 256");
        }
        this.forEncryption = pEncrypt;
        generateRoundKeys(myKey);
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "LEA";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] pInput, int pInOff, byte[] pOutput, int pOutOff) {
        checkBuffer(pInput, pInOff, false);
        checkBuffer(pOutput, pOutOff, true);
        if (this.forEncryption) {
            return encryptBlock(pInput, pInOff, pOutput, pOutOff);
        }
        return decryptBlock(pInput, pInOff, pOutput, pOutOff);
    }

    private static int bufLength(byte[] pBuffer) {
        if (pBuffer == null) {
            return 0;
        }
        return pBuffer.length;
    }

    private static void checkBuffer(byte[] pBuffer, int pOffset, boolean pOutput) {
        int myBufLen = bufLength(pBuffer);
        int myLast = pOffset + 16;
        if (!(pOffset < 0 || myLast < 0) && myLast <= myBufLen) {
            return;
        }
        if (pOutput) {
            throw new OutputLengthException("Output buffer too short.");
        }
        throw new DataLengthException("Input buffer too short.");
    }

    private int encryptBlock(byte[] pInput, int pInOff, byte[] pOutput, int pOutOff) {
        Pack.littleEndianToInt(pInput, pInOff, this.theBlock, 0, 4);
        for (int i = 0; i < this.theRounds; i++) {
            encryptRound(i);
        }
        Pack.intToLittleEndian(this.theBlock, pOutput, pOutOff);
        return 16;
    }

    private void encryptRound(int pRound) {
        int[] myKeys = this.theRoundKeys[pRound];
        int myIndex = (pRound + 3) % 4;
        int myNextIndex = leftIndex(myIndex);
        this.theBlock[myIndex] = ror32((this.theBlock[myNextIndex] ^ myKeys[4]) + (this.theBlock[myIndex] ^ myKeys[5]), 3);
        int myNextIndex2 = leftIndex(myNextIndex);
        this.theBlock[myNextIndex] = ror32((this.theBlock[myNextIndex2] ^ myKeys[2]) + (this.theBlock[myNextIndex] ^ myKeys[3]), 5);
        this.theBlock[myNextIndex2] = rol32((this.theBlock[leftIndex(myNextIndex2)] ^ myKeys[0]) + (this.theBlock[myNextIndex2] ^ myKeys[1]), 9);
    }

    private static int leftIndex(int pIndex) {
        if (pIndex == 0) {
            return 3;
        }
        return pIndex - 1;
    }

    private int decryptBlock(byte[] pInput, int pInOff, byte[] pOutput, int pOutOff) {
        Pack.littleEndianToInt(pInput, pInOff, this.theBlock, 0, 4);
        for (int i = this.theRounds - 1; i >= 0; i--) {
            decryptRound(i);
        }
        Pack.intToLittleEndian(this.theBlock, pOutput, pOutOff);
        return 16;
    }

    private void decryptRound(int pRound) {
        int[] myKeys = this.theRoundKeys[pRound];
        int myPrevIndex = pRound % 4;
        int myIndex = rightIndex(myPrevIndex);
        this.theBlock[myIndex] = (ror32(this.theBlock[myIndex], 9) - (this.theBlock[myPrevIndex] ^ myKeys[0])) ^ myKeys[1];
        int myIndex2 = rightIndex(myIndex);
        this.theBlock[myIndex2] = (rol32(this.theBlock[myIndex2], 5) - (this.theBlock[myIndex] ^ myKeys[2])) ^ myKeys[3];
        int myIndex3 = rightIndex(myIndex2);
        this.theBlock[myIndex3] = (rol32(this.theBlock[myIndex3], 3) - (this.theBlock[myIndex2] ^ myKeys[4])) ^ myKeys[5];
    }

    private static int rightIndex(int pIndex) {
        if (pIndex == 3) {
            return 0;
        }
        return pIndex + 1;
    }

    private void generateRoundKeys(byte[] pKey) {
        this.theRounds = (pKey.length >> 1) + 16;
        this.theRoundKeys = (int[][]) Array.newInstance(Integer.TYPE, this.theRounds, 6);
        int numWords = pKey.length / 4;
        int[] myT = new int[numWords];
        Pack.littleEndianToInt(pKey, 0, myT, 0, numWords);
        switch (numWords) {
            case 4:
                generate128RoundKeys(myT);
                return;
            case 5:
            default:
                generate256RoundKeys(myT);
                return;
            case 6:
                generate192RoundKeys(myT);
                return;
        }
    }

    private void generate128RoundKeys(int[] pWork) {
        for (int i = 0; i < this.theRounds; i++) {
            int myDelta = rol32(DELTA[i & 3], i);
            int j = 0 + 1;
            pWork[0] = rol32(pWork[0] + myDelta, 1);
            int j2 = j + 1;
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j), 3);
            int j3 = j2 + 1;
            pWork[j2] = rol32(pWork[j2] + rol32(myDelta, j2), 6);
            pWork[j3] = rol32(pWork[j3] + rol32(myDelta, j3), 11);
            int[] myKeys = this.theRoundKeys[i];
            myKeys[0] = pWork[0];
            myKeys[1] = pWork[1];
            myKeys[2] = pWork[2];
            myKeys[3] = pWork[1];
            myKeys[4] = pWork[3];
            myKeys[5] = pWork[1];
        }
    }

    private void generate192RoundKeys(int[] pWork) {
        for (int i = 0; i < this.theRounds; i++) {
            int myDelta = rol32(DELTA[i % 6], i);
            int j = 0 + 1;
            pWork[0] = rol32(pWork[0] + rol32(myDelta, 0), 1);
            int j2 = j + 1;
            pWork[j] = rol32(pWork[j] + rol32(myDelta, j), 3);
            int j3 = j2 + 1;
            pWork[j2] = rol32(pWork[j2] + rol32(myDelta, j2), 6);
            int j4 = j3 + 1;
            pWork[j3] = rol32(pWork[j3] + rol32(myDelta, j3), 11);
            int j5 = j4 + 1;
            pWork[j4] = rol32(pWork[j4] + rol32(myDelta, j4), 13);
            pWork[j5] = rol32(pWork[j5] + rol32(myDelta, j5), 17);
            System.arraycopy(pWork, 0, this.theRoundKeys[i], 0, j5 + 1);
        }
    }

    private void generate256RoundKeys(int[] pWork) {
        int index = 0;
        for (int i = 0; i < this.theRounds; i++) {
            int myDelta = rol32(DELTA[i & 7], i);
            int[] myKeys = this.theRoundKeys[i];
            myKeys[0] = rol32(pWork[index & 7] + myDelta, 1);
            int index2 = index + 1;
            int j = 0 + 1;
            pWork[index & 7] = myKeys[0];
            myKeys[j] = rol32(pWork[index2 & 7] + rol32(myDelta, j), 3);
            int index3 = index2 + 1;
            int j2 = j + 1;
            pWork[index2 & 7] = myKeys[j];
            myKeys[j2] = rol32(pWork[index3 & 7] + rol32(myDelta, j2), 6);
            int index4 = index3 + 1;
            int j3 = j2 + 1;
            pWork[index3 & 7] = myKeys[j2];
            myKeys[j3] = rol32(pWork[index4 & 7] + rol32(myDelta, j3), 11);
            int index5 = index4 + 1;
            int j4 = j3 + 1;
            pWork[index4 & 7] = myKeys[j3];
            myKeys[j4] = rol32(pWork[index5 & 7] + rol32(myDelta, j4), 13);
            int index6 = index5 + 1;
            int j5 = j4 + 1;
            pWork[index5 & 7] = myKeys[j4];
            myKeys[j5] = rol32(pWork[index6 & 7] + rol32(myDelta, j5), 17);
            index = index6 + 1;
            pWork[index6 & 7] = myKeys[j5];
        }
    }

    private static int rol32(int pValue, int pBits) {
        return (pValue << pBits) | (pValue >>> (32 - pBits));
    }

    private static int ror32(int pValue, int pBits) {
        return (pValue >>> pBits) | (pValue << (32 - pBits));
    }
}
