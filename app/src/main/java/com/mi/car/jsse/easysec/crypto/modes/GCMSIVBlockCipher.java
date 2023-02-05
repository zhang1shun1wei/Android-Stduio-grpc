package com.mi.car.jsse.easysec.crypto.modes;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.InvalidCipherTextException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.modes.gcm.GCMMultiplier;
import com.mi.car.jsse.easysec.crypto.modes.gcm.Tables4kGCMMultiplier;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.ByteArrayOutputStream;

public class GCMSIVBlockCipher implements AEADBlockCipher {
    private static final byte ADD = -31;
    private static final int AEAD_COMPLETE = 2;
    private static final int BUFLEN = 16;
    private static final int HALFBUFLEN = 8;
    private static final int INIT = 1;
    private static final byte MASK = Byte.MIN_VALUE;
    private static final int MAX_DATALEN = 2147483623;
    private static final int NONCELEN = 12;
    private boolean forEncryption;
    private byte[] macBlock;
    private final GCMSIVHasher theAEADHasher;
    private final BlockCipher theCipher;
    private final GCMSIVHasher theDataHasher;
    private GCMSIVCache theEncData;
    private int theFlags;
    private final byte[] theGHash;
    private byte[] theInitialAEAD;
    private final GCMMultiplier theMultiplier;
    private byte[] theNonce;
    private GCMSIVCache thePlain;
    private final byte[] theReverse;

    public GCMSIVBlockCipher() {
        this(new AESEngine());
    }

    public GCMSIVBlockCipher(BlockCipher pCipher) {
        this(pCipher, new Tables4kGCMMultiplier());
    }

    public GCMSIVBlockCipher(BlockCipher pCipher, GCMMultiplier pMultiplier) {
        this.theGHash = new byte[16];
        this.theReverse = new byte[16];
        this.macBlock = new byte[16];
        if (pCipher.getBlockSize() != 16) {
            throw new IllegalArgumentException("Cipher required with a block size of 16.");
        }
        this.theCipher = pCipher;
        this.theMultiplier = pMultiplier;
        this.theAEADHasher = new GCMSIVHasher();
        this.theDataHasher = new GCMSIVHasher();
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.theCipher;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void init(boolean pEncrypt, CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] myNonce;
        KeyParameter myKey;
        byte[] myInitialAEAD = null;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters myAEAD = (AEADParameters) cipherParameters;
            myInitialAEAD = myAEAD.getAssociatedText();
            myNonce = myAEAD.getNonce();
            myKey = myAEAD.getKey();
        } else if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV myParms = (ParametersWithIV) cipherParameters;
            myNonce = myParms.getIV();
            myKey = (KeyParameter) myParms.getParameters();
        } else {
            throw new IllegalArgumentException("invalid parameters passed to GCM-SIV");
        }
        if (myNonce == null || myNonce.length != 12) {
            throw new IllegalArgumentException("Invalid nonce");
        } else if (myKey == null || !(myKey.getKey().length == 16 || myKey.getKey().length == 32)) {
            throw new IllegalArgumentException("Invalid key");
        } else {
            this.forEncryption = pEncrypt;
            this.theInitialAEAD = myInitialAEAD;
            this.theNonce = myNonce;
            deriveKeys(myKey);
            resetStreams();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.theCipher.getAlgorithmName() + "-GCM-SIV";
    }

    private void checkAEADStatus(int pLen) {
        if ((this.theFlags & 1) == 0) {
            throw new IllegalStateException("Cipher is not initialised");
        } else if ((this.theFlags & 2) != 0) {
            throw new IllegalStateException("AEAD data cannot be processed after ordinary data");
        } else if (this.theAEADHasher.getBytesProcessed() - Long.MIN_VALUE > ((long) (MAX_DATALEN - pLen)) - Long.MIN_VALUE) {
            throw new IllegalStateException("AEAD byte count exceeded");
        }
    }

    private void checkStatus(int pLen) {
        if ((this.theFlags & 1) == 0) {
            throw new IllegalStateException("Cipher is not initialised");
        }
        if ((this.theFlags & 2) == 0) {
            this.theAEADHasher.completeHash();
            this.theFlags |= 2;
        }
        long dataLimit = 2147483623;
        long currBytes = (long) this.thePlain.size();
        if (!this.forEncryption) {
            dataLimit = 2147483623 + 16;
            currBytes = (long) this.theEncData.size();
        }
        if (currBytes - Long.MIN_VALUE > (dataLimit - ((long) pLen)) - Long.MIN_VALUE) {
            throw new IllegalStateException("byte count exceeded");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADByte(byte pByte) {
        checkAEADStatus(1);
        this.theAEADHasher.updateHash(pByte);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void processAADBytes(byte[] pData, int pOffset, int pLen) {
        checkAEADStatus(pLen);
        checkBuffer(pData, pOffset, pLen, false);
        this.theAEADHasher.updateHash(pData, pOffset, pLen);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processByte(byte pByte, byte[] pOutput, int pOutOffset) throws DataLengthException {
        checkStatus(1);
        if (this.forEncryption) {
            this.thePlain.write(pByte);
            this.theDataHasher.updateHash(pByte);
            return 0;
        }
        this.theEncData.write(pByte);
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int processBytes(byte[] pData, int pOffset, int pLen, byte[] pOutput, int pOutOffset) throws DataLengthException {
        checkStatus(pLen);
        checkBuffer(pData, pOffset, pLen, false);
        if (this.forEncryption) {
            this.thePlain.write(pData, pOffset, pLen);
            this.theDataHasher.updateHash(pData, pOffset, pLen);
        } else {
            this.theEncData.write(pData, pOffset, pLen);
        }
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int doFinal(byte[] pOutput, int pOffset) throws IllegalStateException, InvalidCipherTextException {
        checkStatus(0);
        checkBuffer(pOutput, pOffset, getOutputSize(0), true);
        if (this.forEncryption) {
            byte[] myTag = calculateTag();
            int myDataLen = encryptPlain(myTag, pOutput, pOffset) + 16;
            System.arraycopy(myTag, 0, pOutput, this.thePlain.size() + pOffset, 16);
            System.arraycopy(myTag, 0, this.macBlock, 0, this.macBlock.length);
            resetStreams();
            return myDataLen;
        }
        decryptPlain();
        int myDataLen2 = this.thePlain.size();
        System.arraycopy(this.thePlain.getBuffer(), 0, pOutput, pOffset, myDataLen2);
        resetStreams();
        return myDataLen2;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public byte[] getMac() {
        return Arrays.clone(this.macBlock);
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int pLen) {
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public int getOutputSize(int pLen) {
        if (this.forEncryption) {
            return this.thePlain.size() + pLen + 16;
        }
        int myCurr = pLen + this.theEncData.size();
        if (myCurr > 16) {
            return myCurr - 16;
        }
        return 0;
    }

    @Override // com.mi.car.jsse.easysec.crypto.modes.AEADCipher
    public void reset() {
        resetStreams();
    }

    private void resetStreams() {
        if (this.thePlain != null) {
            this.thePlain.clearBuffer();
        }
        this.theAEADHasher.reset();
        this.theDataHasher.reset();
        this.thePlain = new GCMSIVCache();
        this.theEncData = this.forEncryption ? null : new GCMSIVCache();
        this.theFlags &= -3;
        Arrays.fill(this.theGHash, (byte) 0);
        if (this.theInitialAEAD != null) {
            this.theAEADHasher.updateHash(this.theInitialAEAD, 0, this.theInitialAEAD.length);
        }
    }

    private static int bufLength(byte[] pBuffer) {
        if (pBuffer == null) {
            return 0;
        }
        return pBuffer.length;
    }

    private static void checkBuffer(byte[] pBuffer, int pOffset, int pLen, boolean pOutput) {
        int myBufLen = bufLength(pBuffer);
        int myLast = pOffset + pLen;
        if (!(pLen < 0 || pOffset < 0 || myLast < 0) && myLast <= myBufLen) {
            return;
        }
        if (pOutput) {
            throw new OutputLengthException("Output buffer too short.");
        }
        throw new DataLengthException("Input buffer too short.");
    }

    private int encryptPlain(byte[] pCounter, byte[] pTarget, int pOffset) {
        byte[] mySrc = this.thePlain.getBuffer();
        byte[] myCounter = Arrays.clone(pCounter);
        myCounter[15] = (byte) (myCounter[15] | MASK);
        byte[] myMask = new byte[16];
        int myRemaining = this.thePlain.size();
        int myOff = 0;
        while (myRemaining > 0) {
            this.theCipher.processBlock(myCounter, 0, myMask, 0);
            int myLen = Math.min(16, myRemaining);
            xorBlock(myMask, mySrc, myOff, myLen);
            System.arraycopy(myMask, 0, pTarget, pOffset + myOff, myLen);
            myRemaining -= myLen;
            myOff += myLen;
            incrementCounter(myCounter);
        }
        return this.thePlain.size();
    }

    private void decryptPlain() throws InvalidCipherTextException {
        byte[] mySrc = this.theEncData.getBuffer();
        int myRemaining = this.theEncData.size() - 16;
        if (myRemaining < 0) {
            throw new InvalidCipherTextException("Data too short");
        }
        byte[] myExpected = Arrays.copyOfRange(mySrc, myRemaining, myRemaining + 16);
        byte[] myCounter = Arrays.clone(myExpected);
        myCounter[15] = (byte) (myCounter[15] | MASK);
        byte[] myMask = new byte[16];
        int myOff = 0;
        while (myRemaining > 0) {
            this.theCipher.processBlock(myCounter, 0, myMask, 0);
            int myLen = Math.min(16, myRemaining);
            xorBlock(myMask, mySrc, myOff, myLen);
            this.thePlain.write(myMask, 0, myLen);
            this.theDataHasher.updateHash(myMask, 0, myLen);
            myRemaining -= myLen;
            myOff += myLen;
            incrementCounter(myCounter);
        }
        byte[] myTag = calculateTag();
        if (!Arrays.constantTimeAreEqual(myTag, myExpected)) {
            reset();
            throw new InvalidCipherTextException("mac check failed");
        } else {
            System.arraycopy(myTag, 0, this.macBlock, 0, this.macBlock.length);
        }
    }

    private byte[] calculateTag() {
        this.theDataHasher.completeHash();
        byte[] myPolyVal = completePolyVal();
        byte[] myResult = new byte[16];
        for (int i = 0; i < 12; i++) {
            myPolyVal[i] = (byte) (myPolyVal[i] ^ this.theNonce[i]);
        }
        myPolyVal[15] = (byte) (myPolyVal[15] & -129);
        this.theCipher.processBlock(myPolyVal, 0, myResult, 0);
        return myResult;
    }

    private byte[] completePolyVal() {
        byte[] myResult = new byte[16];
        gHashLengths();
        fillReverse(this.theGHash, 0, 16, myResult);
        return myResult;
    }

    private void gHashLengths() {
        byte[] myIn = new byte[16];
        Pack.longToBigEndian(this.theDataHasher.getBytesProcessed() * 8, myIn, 0);
        Pack.longToBigEndian(this.theAEADHasher.getBytesProcessed() * 8, myIn, 8);
        gHASH(myIn);
    }

    /* access modifiers changed from: private */
    /* access modifiers changed from: public */
    private void gHASH(byte[] pNext) {
        xorBlock(this.theGHash, pNext);
        this.theMultiplier.multiplyH(this.theGHash);
    }

    /* access modifiers changed from: private */
    public static void fillReverse(byte[] pInput, int pOffset, int pLength, byte[] pOutput) {
        int i = 0;
        int j = 15;
        while (i < pLength) {
            pOutput[j] = pInput[pOffset + i];
            i++;
            j--;
        }
    }

    private static void xorBlock(byte[] pLeft, byte[] pRight) {
        for (int i = 0; i < 16; i++) {
            pLeft[i] = (byte) (pLeft[i] ^ pRight[i]);
        }
    }

    private static void xorBlock(byte[] pLeft, byte[] pRight, int pOffset, int pLength) {
        for (int i = 0; i < pLength; i++) {
            pLeft[i] = (byte) (pLeft[i] ^ pRight[i + pOffset]);
        }
    }

    private static void incrementCounter(byte[] pCounter) {
        for (int i = 0; i < 4; i++) {
            byte b = (byte) (pCounter[i] + 1);
            pCounter[i] = b;
            if (b != 0) {
                return;
            }
        }
    }

    private static void mulX(byte[] pValue) {
        byte myMask = 0;
        for (int i = 0; i < 16; i++) {
            byte myValue = pValue[i];
            pValue[i] = (byte) (((myValue >> 1) & 127) | myMask);
            myMask = (myValue & 1) == 0 ? 0 : MASK;
        }
        if (myMask != 0) {
            pValue[0] = (byte) (pValue[0] ^ ADD);
        }
    }

    private void deriveKeys(KeyParameter pKey) {
        byte[] myIn = new byte[16];
        byte[] myOut = new byte[16];
        byte[] myResult = new byte[16];
        byte[] myEncKey = new byte[pKey.getKey().length];
        System.arraycopy(this.theNonce, 0, myIn, 4, 12);
        this.theCipher.init(true, pKey);
        this.theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myResult, 0, 8);
        myIn[0] = (byte) (myIn[0] + 1);
        this.theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myResult, 0 + 8, 8);
        myIn[0] = (byte) (myIn[0] + 1);
        this.theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myEncKey, 0, 8);
        myIn[0] = (byte) (myIn[0] + 1);
        int myOff = 0 + 8;
        this.theCipher.processBlock(myIn, 0, myOut, 0);
        System.arraycopy(myOut, 0, myEncKey, myOff, 8);
        if (myEncKey.length == 32) {
            myIn[0] = (byte) (myIn[0] + 1);
            int myOff2 = myOff + 8;
            this.theCipher.processBlock(myIn, 0, myOut, 0);
            System.arraycopy(myOut, 0, myEncKey, myOff2, 8);
            myIn[0] = (byte) (myIn[0] + 1);
            this.theCipher.processBlock(myIn, 0, myOut, 0);
            System.arraycopy(myOut, 0, myEncKey, myOff2 + 8, 8);
        }
        this.theCipher.init(true, new KeyParameter(myEncKey));
        fillReverse(myResult, 0, 16, myOut);
        mulX(myOut);
        this.theMultiplier.init(myOut);
        this.theFlags |= 1;
    }

    /* access modifiers changed from: private */
    public static class GCMSIVCache extends ByteArrayOutputStream {
        GCMSIVCache() {
        }

        /* access modifiers changed from: package-private */
        public byte[] getBuffer() {
            return this.buf;
        }

        /* access modifiers changed from: package-private */
        public void clearBuffer() {
            Arrays.fill(getBuffer(), (byte) 0);
        }
    }

    /* access modifiers changed from: private */
    public class GCMSIVHasher {
        private int numActive;
        private long numHashed;
        private final byte[] theBuffer;
        private final byte[] theByte;

        private GCMSIVHasher() {
            this.theBuffer = new byte[16];
            this.theByte = new byte[1];
        }

        /* access modifiers changed from: package-private */
        public long getBytesProcessed() {
            return this.numHashed;
        }

        /* access modifiers changed from: package-private */
        public void reset() {
            this.numActive = 0;
            this.numHashed = 0;
        }

        /* access modifiers changed from: package-private */
        public void updateHash(byte pByte) {
            this.theByte[0] = pByte;
            updateHash(this.theByte, 0, 1);
        }

        /* access modifiers changed from: package-private */
        public void updateHash(byte[] pBuffer, int pOffset, int pLen) {
            int mySpace = 16 - this.numActive;
            int numProcessed = 0;
            int myRemaining = pLen;
            if (this.numActive > 0 && pLen >= mySpace) {
                System.arraycopy(pBuffer, pOffset, this.theBuffer, this.numActive, mySpace);
                GCMSIVBlockCipher.fillReverse(this.theBuffer, 0, 16, GCMSIVBlockCipher.this.theReverse);
                GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
                numProcessed = 0 + mySpace;
                myRemaining -= mySpace;
                this.numActive = 0;
            }
            while (myRemaining >= 16) {
                GCMSIVBlockCipher.fillReverse(pBuffer, pOffset + numProcessed, 16, GCMSIVBlockCipher.this.theReverse);
                GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
                numProcessed += mySpace;
                myRemaining -= mySpace;
            }
            if (myRemaining > 0) {
                System.arraycopy(pBuffer, pOffset + numProcessed, this.theBuffer, this.numActive, myRemaining);
                this.numActive += myRemaining;
            }
            this.numHashed += (long) pLen;
        }

        /* access modifiers changed from: package-private */
        public void completeHash() {
            if (this.numActive > 0) {
                Arrays.fill(GCMSIVBlockCipher.this.theReverse, (byte) 0);
                GCMSIVBlockCipher.fillReverse(this.theBuffer, 0, this.numActive, GCMSIVBlockCipher.this.theReverse);
                GCMSIVBlockCipher.this.gHASH(GCMSIVBlockCipher.this.theReverse);
            }
        }
    }
}
