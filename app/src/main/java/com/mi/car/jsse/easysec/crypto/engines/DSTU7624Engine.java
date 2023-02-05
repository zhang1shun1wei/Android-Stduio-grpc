package com.mi.car.jsse.easysec.crypto.engines;

import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.DataLengthException;
import com.mi.car.jsse.easysec.crypto.OutputLengthException;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.signers.PSSSigner;
import com.mi.car.jsse.easysec.math.ec.Tnaf;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import com.mi.car.jsse.easysec.util.Arrays;
import com.mi.car.jsse.easysec.util.Pack;

public class DSTU7624Engine implements BlockCipher {
    private static final int ROUNDS_128 = 10;
    private static final int ROUNDS_256 = 14;
    private static final int ROUNDS_512 = 18;
    private static final byte[] S0 = {-88, 67, 95, 6, 107, 117, 108, 89, 113, -33, -121, -107, 23, -16, -40, 9, 109, -13, 29, -53, -55, 77, 44, -81, 121, -32, -105, -3, 111, 75, 69, 57, 62, -35, -93, 79, -76, -74, -102, 14, 31, -65, 21, -31, 73, -46, -109, -58, -110, 114, -98, 97, -47, 99, -6, -18, -12, 25, -43, -83, 88, -92, -69, -95, -36, -14, -125, 55, 66, -28, 122, 50, -100, -52, -85, 74, -113, 110, 4, 39, 46, -25, -30, 90, -106, 22, 35, 43, -62, 101, 102, 15, PSSSigner.TRAILER_IMPLICIT, -87, 71, 65, 52, 72, -4, -73, 106, -120, -91, 83, -122, -7, 91, -37, 56, 123, -61, 30, 34, 51, 36, 40, 54, -57, -78, 59, -114, 119, -70, -11, 20, -97, 8, 85, -101, 76, -2, 96, 92, -38, 24, 70, -51, 125, 33, -80, 63, 27, -119, -1, -21, -124, 105, 58, -99, -41, -45, 112, 103, 64, -75, -34, 93, 48, -111, -79, 120, 17, 1, -27, 0, 104, -104, -96, -59, 2, -90, 116, 45, 11, -94, 118, -77, -66, -50, -67, -82, -23, -118, 49, 28, -20, -15, -103, -108, -86, -10, 38, 47, -17, -24, -116, 53, 3, -44, Byte.MAX_VALUE, -5, 5, -63, 94, -112, 32, 61, -126, -9, -22, 10, 13, 126, -8, 80, 26, -60, 7, 87, -72, 60, 98, -29, -56, -84, 82, 100, Tnaf.POW_2_WIDTH, -48, -39, 19, 12, 18, 41, 81, -71, -49, -42, 115, -115, -127, 84, -64, -19, 78, 68, -89, 42, -123, 37, -26, -54, 124, -117, 86, Byte.MIN_VALUE};
    private static final byte[] S1 = {-50, -69, -21, -110, -22, -53, 19, -63, -23, 58, -42, -78, -46, -112, 23, -8, 66, 21, 86, -76, 101, 28, -120, 67, -59, 92, 54, -70, -11, 87, 103, -115, 49, -10, 100, 88, -98, -12, 34, -86, 117, 15, 2, -79, -33, 109, 115, 77, 124, 38, 46, -9, 8, 93, 68, 62, -97, 20, -56, -82, 84, Tnaf.POW_2_WIDTH, -40, PSSSigner.TRAILER_IMPLICIT, 26, 107, 105, -13, -67, 51, -85, -6, -47, -101, 104, 78, 22, -107, -111, -18, 76, 99, -114, 91, -52, 60, 25, -95, -127, 73, 123, -39, 111, 55, 96, -54, -25, 43, 72, -3, -106, 69, -4, 65, 18, 13, 121, -27, -119, -116, -29, 32, 48, -36, -73, 108, 74, -75, 63, -105, -44, 98, 45, 6, -92, -91, -125, 95, 42, -38, -55, 0, 126, -94, 85, -65, 17, -43, -100, -49, 14, 10, 61, 81, 125, -109, 27, -2, -60, 71, 9, -122, 11, -113, -99, 106, 7, -71, -80, -104, 24, 50, 113, 75, -17, 59, 112, -96, -28, 64, -1, -61, -87, -26, 120, -7, -117, 70, Byte.MIN_VALUE, 30, 56, -31, -72, -88, -32, 12, 35, 118, 29, 37, 36, 5, -15, 110, -108, 40, -102, -124, -24, -93, 79, 119, -45, -123, -30, 82, -14, -126, 80, 122, 47, 116, 83, -77, 97, -81, 57, 53, -34, -51, 31, -103, -84, -83, 114, 44, -35, -48, -121, -66, 94, -90, -20, 4, -58, 3, 52, -5, -37, 89, -74, -62, 1, -16, 90, -19, -89, 102, 33, Byte.MAX_VALUE, -118, 39, -57, -64, 41, -41};
    private static final byte[] S2 = {-109, -39, -102, -75, -104, 34, 69, -4, -70, 106, -33, 2, -97, -36, 81, 89, 74, 23, 43, -62, -108, -12, -69, -93, 98, -28, 113, -44, -51, 112, 22, -31, 73, 60, -64, -40, 92, -101, -83, -123, 83, -95, 122, -56, 45, -32, -47, 114, -90, 44, -60, -29, 118, 120, -73, -76, 9, 59, 14, 65, 76, -34, -78, -112, 37, -91, -41, 3, 17, 0, -61, 46, -110, -17, 78, 18, -99, 125, -53, 53, Tnaf.POW_2_WIDTH, -43, 79, -98, 77, -87, 85, -58, -48, 123, 24, -105, -45, 54, -26, 72, 86, -127, -113, 119, -52, -100, -71, -30, -84, -72, 47, 21, -92, 124, -38, 56, 30, 11, 5, -42, 20, 110, 108, 126, 102, -3, -79, -27, 96, -81, 94, 51, -121, -55, -16, 93, 109, 63, -120, -115, -57, -9, 29, -23, -20, -19, Byte.MIN_VALUE, 41, 39, -49, -103, -88, 80, 15, 55, 36, 40, 48, -107, -46, 62, 91, 64, -125, -77, 105, 87, 31, 7, 28, -118, PSSSigner.TRAILER_IMPLICIT, 32, -21, -50, -114, -85, -18, 49, -94, 115, -7, -54, 58, 26, -5, 13, -63, -2, -6, -14, 111, -67, -106, -35, 67, 82, -74, 8, -13, -82, -66, 25, -119, 50, 38, -80, -22, 75, 100, -124, -126, 107, -11, 121, -65, 1, 95, 117, 99, 27, 35, 61, 104, 42, 101, -24, -111, -10, -1, 19, 88, -15, 71, 10, Byte.MAX_VALUE, -59, -89, -25, 97, 90, 6, 70, 68, 66, 4, -96, -37, 57, -122, 84, -86, -116, 52, 33, -117, -8, 12, 116, 103};
    private static final byte[] S3 = {104, -115, -54, 77, 115, 75, 78, 42, -44, 82, 38, -77, 84, 30, 25, 31, 34, 3, 70, 61, 45, 74, 83, -125, 19, -118, -73, -43, 37, 121, -11, -67, 88, 47, 13, 2, -19, 81, -98, 17, -14, 62, 85, 94, -47, 22, 60, 102, 112, 93, -13, 69, 64, -52, -24, -108, 86, 8, -50, 26, 58, -46, -31, -33, -75, 56, 110, 14, -27, -12, -7, -122, -23, 79, -42, -123, 35, -49, 50, -103, 49, 20, -82, -18, -56, 72, -45, 48, -95, -110, 65, -79, 24, -60, 44, 113, 114, 68, 21, -3, 55, -66, 95, -86, -101, -120, -40, -85, -119, -100, -6, 96, -22, PSSSigner.TRAILER_IMPLICIT, 98, 12, 36, -90, -88, -20, 103, 32, -37, 124, 40, -35, -84, 91, 52, 126, Tnaf.POW_2_WIDTH, -15, 123, -113, 99, -96, 5, -102, 67, 119, 33, -65, 39, 9, -61, -97, -74, -41, 41, -62, -21, -64, -92, -117, -116, 29, -5, -1, -63, -78, -105, 46, -8, 101, -10, 117, 7, 4, 73, 51, -28, -39, -71, -48, 66, -57, 108, -112, 0, -114, 111, 80, 1, -59, -38, 71, 63, -51, 105, -94, -30, 122, -89, -58, -109, 15, 10, 6, -26, 43, -106, -93, 28, -81, 106, 18, -124, 57, -25, -80, -126, -9, -2, -99, -121, 92, -127, 53, -34, -76, -91, -4, Byte.MIN_VALUE, -17, -53, -69, 107, 118, -70, 90, 125, 120, 11, -107, -29, -83, 116, -104, 59, 54, 100, 109, -36, -16, 89, -87, 76, 23, Byte.MAX_VALUE, -111, -72, -55, 87, 27, -32, 97};
    private static final byte[] T0 = {-92, -94, -87, -59, 78, -55, 3, -39, 126, 15, -46, -83, -25, -45, 39, 91, -29, -95, -24, -26, 124, 42, 85, 12, -122, 57, -41, -115, -72, 18, 111, 40, -51, -118, 112, 86, 114, -7, -65, 79, 115, -23, -9, 87, 22, -84, 80, -64, -99, -73, 71, 113, 96, -60, 116, 67, 108, 31, -109, 119, -36, -50, 32, -116, -103, 95, 68, 1, -11, 30, -121, 94, 97, 44, 75, 29, -127, 21, -12, 35, -42, -22, -31, 103, -15, Byte.MAX_VALUE, -2, -38, 60, 7, 83, 106, -124, -100, -53, 2, -125, 51, -35, 53, -30, 89, 90, -104, -91, -110, 100, 4, 6, Tnaf.POW_2_WIDTH, 77, 28, -105, 8, 49, -18, -85, 5, -81, 121, -96, 24, 70, 109, -4, -119, -44, -57, -1, -16, -49, 66, -111, -8, 104, 10, 101, -114, -74, -3, -61, -17, 120, 76, -52, -98, 48, 46, PSSSigner.TRAILER_IMPLICIT, 11, 84, 26, -90, -69, 38, Byte.MIN_VALUE, 72, -108, 50, 125, -89, 63, -82, 34, 61, 102, -86, -10, 0, 93, -67, 74, -32, 59, -76, 23, -117, -97, 118, -80, 36, -102, 37, 99, -37, -21, 122, 62, 92, -77, -79, 41, -14, -54, 88, 110, -40, -88, 47, 117, -33, 20, -5, 19, 73, -120, -78, -20, -28, 52, 45, -106, -58, 58, -19, -107, 14, -27, -123, 107, 64, 33, -101, 9, 25, 43, 82, -34, 69, -93, -6, 81, -62, -75, -47, -112, -71, -13, 55, -63, 13, -70, 65, 17, 56, 123, -66, -48, -43, 105, 54, -56, 98, 27, -126, -113};
    private static final byte[] T1 = {-125, -14, 42, -21, -23, -65, 123, -100, 52, -106, -115, -104, -71, 105, -116, 41, 61, -120, 104, 6, 57, 17, 76, 14, -96, 86, 64, -110, 21, PSSSigner.TRAILER_IMPLICIT, -77, -36, 111, -8, 38, -70, -66, -67, 49, -5, -61, -2, Byte.MIN_VALUE, 97, -31, 122, 50, -46, 112, 32, -95, 69, -20, -39, 26, 93, -76, -40, 9, -91, 85, -114, 55, 118, -87, 103, Tnaf.POW_2_WIDTH, 23, 54, 101, -79, -107, 98, 89, 116, -93, 80, 47, 75, -56, -48, -113, -51, -44, 60, -122, 18, 29, 35, -17, -12, 83, 25, 53, -26, Byte.MAX_VALUE, 94, -42, 121, 81, 34, 20, -9, 30, 74, 66, -101, 65, 115, 45, -63, 92, -90, -94, -32, 46, -45, 40, -69, -55, -82, 106, -47, 90, 48, -112, -124, -7, -78, 88, -49, 126, -59, -53, -105, -28, 22, 108, -6, -80, 109, 31, 82, -103, 13, 78, 3, -111, -62, 77, 100, 119, -97, -35, -60, 73, -118, -102, 36, 56, -89, 87, -123, -57, 124, 125, -25, -10, -73, -84, 39, 70, -34, -33, 59, -41, -98, 43, 11, -43, 19, 117, -16, 114, -74, -99, 27, 1, 63, 68, -27, -121, -3, 7, -15, -85, -108, 24, -22, -4, 58, -126, 95, 5, 84, -37, 0, -117, -29, 72, 12, -54, 120, -119, 10, -1, 62, 91, -127, -18, 113, -30, -38, 44, -72, -75, -52, 110, -88, 107, -83, 96, -58, 8, 4, 2, -24, -11, 79, -92, -13, -64, -50, 67, 37, 28, 33, 51, 15, -81, 71, -19, 102, 99, -109, -86};
    private static final byte[] T2 = {69, -44, 11, 67, -15, 114, -19, -92, -62, 56, -26, 113, -3, -74, 58, -107, 80, 68, 75, -30, 116, 107, 30, 17, 90, -58, -76, -40, -91, -118, 112, -93, -88, -6, 5, -39, -105, 64, -55, -112, -104, -113, -36, 18, 49, 44, 71, 106, -103, -82, -56, Byte.MAX_VALUE, -7, 79, 93, -106, 111, -12, -77, 57, 33, -38, -100, -123, -98, 59, -16, -65, -17, 6, -18, -27, 95, 32, Tnaf.POW_2_WIDTH, -52, 60, 84, 74, 82, -108, 14, -64, 40, -10, 86, 96, -94, -29, 15, -20, -99, 36, -125, 126, -43, 124, -21, 24, -41, -51, -35, 120, -1, -37, -95, 9, -48, 118, -124, 117, -69, 29, 26, 47, -80, -2, -42, 52, 99, 53, -46, 42, 89, 109, 77, 119, -25, -114, 97, -49, -97, -50, 39, -11, Byte.MIN_VALUE, -122, -57, -90, -5, -8, -121, -85, 98, 63, -33, 72, 0, 20, -102, -67, 91, 4, -110, 2, 37, 101, 76, 83, 12, -14, 41, -81, 23, 108, 65, 48, -23, -109, 85, -9, -84, 104, 38, -60, 125, -54, 122, 62, -96, 55, 3, -63, 54, 105, 102, 8, 22, -89, PSSSigner.TRAILER_IMPLICIT, -59, -45, 34, -73, 19, 70, 50, -24, 87, -120, 43, -127, -78, 78, 100, 28, -86, -111, 88, 46, -101, 92, 27, 81, 115, 66, 35, 1, 110, -13, 13, -66, 61, 10, 45, 31, 103, 51, 25, 123, 94, -22, -34, -117, -53, -87, -116, -115, -83, 73, -126, -28, -70, -61, 21, -47, -32, -119, -4, -79, -71, -75, 7, 121, -72, -31};
    private static final byte[] T3 = {-78, -74, 35, 17, -89, -120, -59, -90, 57, -113, -60, -24, 115, 34, 67, -61, -126, 39, -51, 24, 81, 98, 45, -9, 92, 14, 59, -3, -54, -101, 13, 15, 121, -116, Tnaf.POW_2_WIDTH, 76, 116, 28, 10, -114, 124, -108, 7, -57, 94, 20, -95, 33, 87, 80, 78, -87, Byte.MIN_VALUE, -39, -17, 100, 65, -49, 60, -18, 46, 19, 41, -70, 52, 90, -82, -118, 97, 51, 18, -71, 85, -88, 21, 5, -10, 3, 6, 73, -75, 37, 9, 22, 12, 42, 56, -4, 32, -12, -27, Byte.MAX_VALUE, -41, 49, 43, 102, 111, -1, 114, -122, -16, -93, 47, 120, 0, PSSSigner.TRAILER_IMPLICIT, -52, -30, -80, -15, 66, -76, 48, 95, 96, 4, -20, -91, -29, -117, -25, 29, -65, -124, 123, -26, -127, -8, -34, -40, -46, 23, -50, 75, 71, -42, 105, 108, 25, -103, -102, 1, -77, -123, -79, -7, 89, -62, 55, -23, -56, -96, -19, 79, -119, 104, 109, -43, 38, -111, -121, 88, -67, -55, -104, -36, 117, -64, 118, -11, 103, 107, 126, -21, 82, -53, -47, 91, -97, 11, -37, 64, -110, 26, -6, -84, -28, -31, 113, 31, 101, -115, -105, -98, -107, -112, 93, -73, -63, -81, 84, -5, 2, -32, 53, -69, 58, 77, -83, 44, 61, 86, 8, 27, 74, -109, 106, -85, -72, 122, -14, 125, -38, 63, -2, 62, -66, -22, -86, 68, -58, -48, 54, 72, 112, -106, 119, 36, 83, -33, -13, -125, 40, 50, 69, 30, -92, -45, -94, 70, 110, -100, -35, 99, -44, -99};
    private boolean forEncryption;
    private long[] internalState;
    private long[][] roundKeys;
    private int roundsAmount;
    private int wordsInBlock;
    private int wordsInKey;
    private long[] workingKey;

    public DSTU7624Engine(int blockBitLength) throws IllegalArgumentException {
        if (blockBitLength == 128 || blockBitLength == 256 || blockBitLength == 512) {
            this.wordsInBlock = blockBitLength >>> 6;
            this.internalState = new long[this.wordsInBlock];
            return;
        }
        throw new IllegalArgumentException("unsupported block length: only 128/256/512 are allowed");
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void init(boolean forEncryption2, CipherParameters params) throws IllegalArgumentException {
        if (!(params instanceof KeyParameter)) {
            throw new IllegalArgumentException("Invalid parameter passed to DSTU7624Engine init");
        }
        this.forEncryption = forEncryption2;
        byte[] keyBytes = ((KeyParameter) params).getKey();
        int keyBitLength = keyBytes.length << 3;
        int blockBitLength = this.wordsInBlock << 6;
        if (keyBitLength != 128 && keyBitLength != 256 && keyBitLength != 512) {
            throw new IllegalArgumentException("unsupported key length: only 128/256/512 are allowed");
        } else if (keyBitLength == blockBitLength || keyBitLength == blockBitLength * 2) {
            switch (keyBitLength) {
                case 128:
                    this.roundsAmount = 10;
                    break;
                case 256:
                    this.roundsAmount = 14;
                    break;
                case 512:
                    this.roundsAmount = 18;
                    break;
            }
            this.wordsInKey = keyBitLength >>> 6;
            this.roundKeys = new long[(this.roundsAmount + 1)][];
            for (int roundKeyIndex = 0; roundKeyIndex < this.roundKeys.length; roundKeyIndex++) {
                this.roundKeys[roundKeyIndex] = new long[this.wordsInBlock];
            }
            this.workingKey = new long[this.wordsInKey];
            if (keyBytes.length != (keyBitLength >>> 3)) {
                throw new IllegalArgumentException("Invalid key parameter passed to DSTU7624Engine init");
            }
            Pack.littleEndianToLong(keyBytes, 0, this.workingKey);
            long[] tempKeys = new long[this.wordsInBlock];
            workingKeyExpandKT(this.workingKey, tempKeys);
            workingKeyExpandEven(this.workingKey, tempKeys);
            workingKeyExpandOdd();
        } else {
            throw new IllegalArgumentException("Unsupported key length");
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public String getAlgorithmName() {
        return "DSTU7624";
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int getBlockSize() {
        return this.wordsInBlock << 3;
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public int processBlock(byte[] in, int inOff, byte[] out, int outOff) throws DataLengthException, IllegalStateException {
        if (this.workingKey == null) {
            throw new IllegalStateException("DSTU7624Engine not initialised");
        } else if (getBlockSize() + inOff > in.length) {
            throw new DataLengthException("Input buffer too short");
        } else if (getBlockSize() + outOff > out.length) {
            throw new OutputLengthException("Output buffer too short");
        } else {
            if (this.forEncryption) {
                switch (this.wordsInBlock) {
                    case 2:
                        encryptBlock_128(in, inOff, out, outOff);
                        break;
                    default:
                        Pack.littleEndianToLong(in, inOff, this.internalState);
                        addRoundKey(0);
                        int round = 0;
                        while (true) {
                            subBytes();
                            shiftRows();
                            mixColumns();
                            round++;
                            if (round == this.roundsAmount) {
                                addRoundKey(this.roundsAmount);
                                Pack.longToLittleEndian(this.internalState, out, outOff);
                                break;
                            } else {
                                xorRoundKey(round);
                            }
                        }
                }
            } else {
                switch (this.wordsInBlock) {
                    case 2:
                        decryptBlock_128(in, inOff, out, outOff);
                        break;
                    default:
                        Pack.littleEndianToLong(in, inOff, this.internalState);
                        subRoundKey(this.roundsAmount);
                        int round2 = this.roundsAmount;
                        while (true) {
                            mixColumnsInv();
                            invShiftRows();
                            invSubBytes();
                            round2--;
                            if (round2 == 0) {
                                subRoundKey(0);
                                Pack.longToLittleEndian(this.internalState, out, outOff);
                                break;
                            } else {
                                xorRoundKey(round2);
                            }
                        }
                }
            }
            return getBlockSize();
        }
    }

    @Override // com.mi.car.jsse.easysec.crypto.BlockCipher
    public void reset() {
        Arrays.fill(this.internalState, 0);
    }

    private void addRoundKey(int round) {
        long[] roundKey = this.roundKeys[round];
        for (int i = 0; i < this.wordsInBlock; i++) {
            long[] jArr = this.internalState;
            jArr[i] = jArr[i] + roundKey[i];
        }
    }

    private void subRoundKey(int round) {
        long[] roundKey = this.roundKeys[round];
        for (int i = 0; i < this.wordsInBlock; i++) {
            long[] jArr = this.internalState;
            jArr[i] = jArr[i] - roundKey[i];
        }
    }

    private void xorRoundKey(int round) {
        long[] roundKey = this.roundKeys[round];
        for (int i = 0; i < this.wordsInBlock; i++) {
            long[] jArr = this.internalState;
            jArr[i] = jArr[i] ^ roundKey[i];
        }
    }

    private void workingKeyExpandKT(long[] workingKey2, long[] tempKeys) {
        long[] k0 = new long[this.wordsInBlock];
        long[] k1 = new long[this.wordsInBlock];
        this.internalState = new long[this.wordsInBlock];
        long[] jArr = this.internalState;
        jArr[0] = jArr[0] + ((long) (this.wordsInBlock + this.wordsInKey + 1));
        if (this.wordsInBlock == this.wordsInKey) {
            System.arraycopy(workingKey2, 0, k0, 0, k0.length);
            System.arraycopy(workingKey2, 0, k1, 0, k1.length);
        } else {
            System.arraycopy(workingKey2, 0, k0, 0, this.wordsInBlock);
            System.arraycopy(workingKey2, this.wordsInBlock, k1, 0, this.wordsInBlock);
        }
        for (int wordIndex = 0; wordIndex < this.internalState.length; wordIndex++) {
            long[] jArr2 = this.internalState;
            jArr2[wordIndex] = jArr2[wordIndex] + k0[wordIndex];
        }
        subBytes();
        shiftRows();
        mixColumns();
        for (int wordIndex2 = 0; wordIndex2 < this.internalState.length; wordIndex2++) {
            long[] jArr3 = this.internalState;
            jArr3[wordIndex2] = jArr3[wordIndex2] ^ k1[wordIndex2];
        }
        subBytes();
        shiftRows();
        mixColumns();
        for (int wordIndex3 = 0; wordIndex3 < this.internalState.length; wordIndex3++) {
            long[] jArr4 = this.internalState;
            jArr4[wordIndex3] = jArr4[wordIndex3] + k0[wordIndex3];
        }
        subBytes();
        shiftRows();
        mixColumns();
        System.arraycopy(this.internalState, 0, tempKeys, 0, this.wordsInBlock);
    }

    private void workingKeyExpandEven(long[] workingKey2, long[] tempKey) {
        long[] initialData = new long[this.wordsInKey];
        long[] tempRoundKey = new long[this.wordsInBlock];
        int round = 0;
        System.arraycopy(workingKey2, 0, initialData, 0, this.wordsInKey);
        long tmv = 281479271743489L;
        while (true) {
            for (int wordIndex = 0; wordIndex < this.wordsInBlock; wordIndex++) {
                tempRoundKey[wordIndex] = tempKey[wordIndex] + tmv;
            }
            for (int wordIndex2 = 0; wordIndex2 < this.wordsInBlock; wordIndex2++) {
                this.internalState[wordIndex2] = initialData[wordIndex2] + tempRoundKey[wordIndex2];
            }
            subBytes();
            shiftRows();
            mixColumns();
            for (int wordIndex3 = 0; wordIndex3 < this.wordsInBlock; wordIndex3++) {
                long[] jArr = this.internalState;
                jArr[wordIndex3] = jArr[wordIndex3] ^ tempRoundKey[wordIndex3];
            }
            subBytes();
            shiftRows();
            mixColumns();
            for (int wordIndex4 = 0; wordIndex4 < this.wordsInBlock; wordIndex4++) {
                long[] jArr2 = this.internalState;
                jArr2[wordIndex4] = jArr2[wordIndex4] + tempRoundKey[wordIndex4];
            }
            System.arraycopy(this.internalState, 0, this.roundKeys[round], 0, this.wordsInBlock);
            if (this.roundsAmount != round) {
                if (this.wordsInBlock != this.wordsInKey) {
                    round += 2;
                    tmv <<= 1;
                    for (int wordIndex5 = 0; wordIndex5 < this.wordsInBlock; wordIndex5++) {
                        tempRoundKey[wordIndex5] = tempKey[wordIndex5] + tmv;
                    }
                    for (int wordIndex6 = 0; wordIndex6 < this.wordsInBlock; wordIndex6++) {
                        this.internalState[wordIndex6] = initialData[this.wordsInBlock + wordIndex6] + tempRoundKey[wordIndex6];
                    }
                    subBytes();
                    shiftRows();
                    mixColumns();
                    for (int wordIndex7 = 0; wordIndex7 < this.wordsInBlock; wordIndex7++) {
                        long[] jArr3 = this.internalState;
                        jArr3[wordIndex7] = jArr3[wordIndex7] ^ tempRoundKey[wordIndex7];
                    }
                    subBytes();
                    shiftRows();
                    mixColumns();
                    for (int wordIndex8 = 0; wordIndex8 < this.wordsInBlock; wordIndex8++) {
                        long[] jArr4 = this.internalState;
                        jArr4[wordIndex8] = jArr4[wordIndex8] + tempRoundKey[wordIndex8];
                    }
                    System.arraycopy(this.internalState, 0, this.roundKeys[round], 0, this.wordsInBlock);
                    if (this.roundsAmount == round) {
                        return;
                    }
                }
                round += 2;
                tmv <<= 1;
                long temp = initialData[0];
                for (int i = 1; i < initialData.length; i++) {
                    initialData[i - 1] = initialData[i];
                }
                initialData[initialData.length - 1] = temp;
            } else {
                return;
            }
        }
    }

    private void workingKeyExpandOdd() {
        for (int roundIndex = 1; roundIndex < this.roundsAmount; roundIndex += 2) {
            rotateLeft(this.roundKeys[roundIndex - 1], this.roundKeys[roundIndex]);
        }
    }

    private void decryptBlock_128(byte[] in, int inOff, byte[] out, int outOff) {
        long c0 = Pack.littleEndianToLong(in, inOff);
        long c1 = Pack.littleEndianToLong(in, inOff + 8);
        long[] roundKey = this.roundKeys[this.roundsAmount];
        long c02 = c0 - roundKey[0];
        long c12 = c1 - roundKey[1];
        int round = this.roundsAmount;
        while (true) {
            long c03 = mixColumnInv(c02);
            long c13 = mixColumnInv(c12);
            int lo0 = (int) c03;
            int hi0 = (int) (c03 >>> 32);
            int lo1 = (int) c13;
            int hi1 = (int) (c13 >>> 32);
            long c04 = (((long) ((T0[lo0 & GF2Field.MASK] & 255) | ((T1[(lo0 >>> 8) & GF2Field.MASK] & 255) << 8) | ((T2[(lo0 >>> 16) & GF2Field.MASK] & 255) << 16) | (T3[lo0 >>> 24] << 24))) & 4294967295L) | (((long) ((((T0[hi1 & GF2Field.MASK] & 255) | ((T1[(hi1 >>> 8) & GF2Field.MASK] & 255) << 8)) | ((T2[(hi1 >>> 16) & GF2Field.MASK] & 255) << 16)) | (T3[hi1 >>> 24] << 24))) << 32);
            long c14 = (((long) ((T0[lo1 & GF2Field.MASK] & 255) | ((T1[(lo1 >>> 8) & GF2Field.MASK] & 255) << 8) | ((T2[(lo1 >>> 16) & GF2Field.MASK] & 255) << 16) | (T3[lo1 >>> 24] << 24))) & 4294967295L) | (((long) ((((T0[hi0 & GF2Field.MASK] & 255) | ((T1[(hi0 >>> 8) & GF2Field.MASK] & 255) << 8)) | ((T2[(hi0 >>> 16) & GF2Field.MASK] & 255) << 16)) | (T3[hi0 >>> 24] << 24))) << 32);
            round--;
            if (round == 0) {
                long[] roundKey2 = this.roundKeys[0];
                Pack.longToLittleEndian(c04 - roundKey2[0], out, outOff);
                Pack.longToLittleEndian(c14 - roundKey2[1], out, outOff + 8);
                return;
            }
            long[] roundKey3 = this.roundKeys[round];
            c02 = c04 ^ roundKey3[0];
            c12 = c14 ^ roundKey3[1];
        }
    }

    private void encryptBlock_128(byte[] in, int inOff, byte[] out, int outOff) {
        long c0 = Pack.littleEndianToLong(in, inOff);
        long c1 = Pack.littleEndianToLong(in, inOff + 8);
        long[] roundKey = this.roundKeys[0];
        long c02 = c0 + roundKey[0];
        long c12 = c1 + roundKey[1];
        int round = 0;
        while (true) {
            int lo0 = (int) c02;
            int hi0 = (int) (c02 >>> 32);
            int lo1 = (int) c12;
            int hi1 = (int) (c12 >>> 32);
            long c03 = mixColumn((((long) ((S0[lo0 & GF2Field.MASK] & 255) | ((S1[(lo0 >>> 8) & GF2Field.MASK] & 255) << 8) | ((S2[(lo0 >>> 16) & GF2Field.MASK] & 255) << 16) | (S3[lo0 >>> 24] << 24))) & 4294967295L) | (((long) ((((S0[hi1 & GF2Field.MASK] & 255) | ((S1[(hi1 >>> 8) & GF2Field.MASK] & 255) << 8)) | ((S2[(hi1 >>> 16) & GF2Field.MASK] & 255) << 16)) | (S3[hi1 >>> 24] << 24))) << 32));
            long c13 = mixColumn((((long) ((S0[lo1 & GF2Field.MASK] & 255) | ((S1[(lo1 >>> 8) & GF2Field.MASK] & 255) << 8) | ((S2[(lo1 >>> 16) & GF2Field.MASK] & 255) << 16) | (S3[lo1 >>> 24] << 24))) & 4294967295L) | (((long) ((((S0[hi0 & GF2Field.MASK] & 255) | ((S1[(hi0 >>> 8) & GF2Field.MASK] & 255) << 8)) | ((S2[(hi0 >>> 16) & GF2Field.MASK] & 255) << 16)) | (S3[hi0 >>> 24] << 24))) << 32));
            round++;
            if (round == this.roundsAmount) {
                long[] roundKey2 = this.roundKeys[this.roundsAmount];
                Pack.longToLittleEndian(c03 + roundKey2[0], out, outOff);
                Pack.longToLittleEndian(c13 + roundKey2[1], out, outOff + 8);
                return;
            }
            long[] roundKey3 = this.roundKeys[round];
            c02 = c03 ^ roundKey3[0];
            c12 = c13 ^ roundKey3[1];
        }
    }

    private void subBytes() {
        for (int i = 0; i < this.wordsInBlock; i++) {
            long u = this.internalState[i];
            int lo = (int) u;
            int hi = (int) (u >>> 32);
            this.internalState[i] = (((long) ((S0[lo & GF2Field.MASK] & 255) | ((S1[(lo >>> 8) & GF2Field.MASK] & 255) << 8) | ((S2[(lo >>> 16) & GF2Field.MASK] & 255) << 16) | (S3[lo >>> 24] << 24))) & 4294967295L) | (((long) ((((S0[hi & GF2Field.MASK] & 255) | ((S1[(hi >>> 8) & GF2Field.MASK] & 255) << 8)) | ((S2[(hi >>> 16) & GF2Field.MASK] & 255) << 16)) | (S3[hi >>> 24] << 24))) << 32);
        }
    }

    private void invSubBytes() {
        for (int i = 0; i < this.wordsInBlock; i++) {
            long u = this.internalState[i];
            int lo = (int) u;
            int hi = (int) (u >>> 32);
            this.internalState[i] = (((long) ((T0[lo & GF2Field.MASK] & 255) | ((T1[(lo >>> 8) & GF2Field.MASK] & 255) << 8) | ((T2[(lo >>> 16) & GF2Field.MASK] & 255) << 16) | (T3[lo >>> 24] << 24))) & 4294967295L) | (((long) ((((T0[hi & GF2Field.MASK] & 255) | ((T1[(hi >>> 8) & GF2Field.MASK] & 255) << 8)) | ((T2[(hi >>> 16) & GF2Field.MASK] & 255) << 16)) | (T3[hi >>> 24] << 24))) << 32);
        }
    }

    private void shiftRows() {
        switch (this.wordsInBlock) {
            case 2:
                long c0 = this.internalState[0];
                long c1 = this.internalState[1];
                long d = (c0 ^ c1) & -4294967296L;
                this.internalState[0] = c0 ^ d;
                this.internalState[1] = c1 ^ d;
                return;
            case 4:
                long c02 = this.internalState[0];
                long c12 = this.internalState[1];
                long c2 = this.internalState[2];
                long c3 = this.internalState[3];
                long d2 = (c02 ^ c2) & -4294967296L;
                long c03 = c02 ^ d2;
                long c22 = c2 ^ d2;
                long d3 = (c12 ^ c3) & 281474976645120L;
                long c13 = c12 ^ d3;
                long c32 = c3 ^ d3;
                long d4 = (c03 ^ c13) & -281470681808896L;
                long c04 = c03 ^ d4;
                long c14 = c13 ^ d4;
                long d5 = (c22 ^ c32) & -281470681808896L;
                this.internalState[0] = c04;
                this.internalState[1] = c14;
                this.internalState[2] = c22 ^ d5;
                this.internalState[3] = c32 ^ d5;
                return;
            case 8:
                long c05 = this.internalState[0];
                long c15 = this.internalState[1];
                long c23 = this.internalState[2];
                long c33 = this.internalState[3];
                long c4 = this.internalState[4];
                long c5 = this.internalState[5];
                long c6 = this.internalState[6];
                long c7 = this.internalState[7];
                long d6 = (c05 ^ c4) & -4294967296L;
                long c06 = c05 ^ d6;
                long c42 = c4 ^ d6;
                long d7 = (c15 ^ c5) & 72057594021150720L;
                long c16 = c15 ^ d7;
                long c52 = c5 ^ d7;
                long d8 = (c23 ^ c6) & 281474976645120L;
                long c24 = c23 ^ d8;
                long c62 = c6 ^ d8;
                long d9 = (c33 ^ c7) & 1099511627520L;
                long c34 = c33 ^ d9;
                long c72 = c7 ^ d9;
                long d10 = (c06 ^ c24) & -281470681808896L;
                long c07 = c06 ^ d10;
                long c25 = c24 ^ d10;
                long d11 = (c16 ^ c34) & 72056494543077120L;
                long c17 = c16 ^ d11;
                long c35 = c34 ^ d11;
                long d12 = (c42 ^ c62) & -281470681808896L;
                long c43 = c42 ^ d12;
                long c63 = c62 ^ d12;
                long d13 = (c52 ^ c72) & 72056494543077120L;
                long c53 = c52 ^ d13;
                long c73 = c72 ^ d13;
                long d14 = (c07 ^ c17) & -71777214294589696L;
                long c08 = c07 ^ d14;
                long c18 = c17 ^ d14;
                long d15 = (c25 ^ c35) & -71777214294589696L;
                long c26 = c25 ^ d15;
                long c36 = c35 ^ d15;
                long d16 = (c43 ^ c53) & -71777214294589696L;
                long c44 = c43 ^ d16;
                long c54 = c53 ^ d16;
                long d17 = (c63 ^ c73) & -71777214294589696L;
                this.internalState[0] = c08;
                this.internalState[1] = c18;
                this.internalState[2] = c26;
                this.internalState[3] = c36;
                this.internalState[4] = c44;
                this.internalState[5] = c54;
                this.internalState[6] = c63 ^ d17;
                this.internalState[7] = c73 ^ d17;
                return;
            default:
                throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
    }

    private void invShiftRows() {
        switch (this.wordsInBlock) {
            case 2:
                long c0 = this.internalState[0];
                long c1 = this.internalState[1];
                long d = (c0 ^ c1) & -4294967296L;
                this.internalState[0] = c0 ^ d;
                this.internalState[1] = c1 ^ d;
                return;
            case 4:
                long c02 = this.internalState[0];
                long c12 = this.internalState[1];
                long c2 = this.internalState[2];
                long c3 = this.internalState[3];
                long d2 = (c02 ^ c12) & -281470681808896L;
                long c03 = c02 ^ d2;
                long c13 = c12 ^ d2;
                long d3 = (c2 ^ c3) & -281470681808896L;
                long c22 = c2 ^ d3;
                long c32 = c3 ^ d3;
                long d4 = (c03 ^ c22) & -4294967296L;
                long c04 = c03 ^ d4;
                long c23 = c22 ^ d4;
                long d5 = (c13 ^ c32) & 281474976645120L;
                this.internalState[0] = c04;
                this.internalState[1] = c13 ^ d5;
                this.internalState[2] = c23;
                this.internalState[3] = c32 ^ d5;
                return;
            case 8:
                long c05 = this.internalState[0];
                long c14 = this.internalState[1];
                long c24 = this.internalState[2];
                long c33 = this.internalState[3];
                long c4 = this.internalState[4];
                long c5 = this.internalState[5];
                long c6 = this.internalState[6];
                long c7 = this.internalState[7];
                long d6 = (c05 ^ c14) & -71777214294589696L;
                long c06 = c05 ^ d6;
                long c15 = c14 ^ d6;
                long d7 = (c24 ^ c33) & -71777214294589696L;
                long c25 = c24 ^ d7;
                long c34 = c33 ^ d7;
                long d8 = (c4 ^ c5) & -71777214294589696L;
                long c42 = c4 ^ d8;
                long c52 = c5 ^ d8;
                long d9 = (c6 ^ c7) & -71777214294589696L;
                long c62 = c6 ^ d9;
                long c72 = c7 ^ d9;
                long d10 = (c06 ^ c25) & -281470681808896L;
                long c07 = c06 ^ d10;
                long c26 = c25 ^ d10;
                long d11 = (c15 ^ c34) & 72056494543077120L;
                long c16 = c15 ^ d11;
                long c35 = c34 ^ d11;
                long d12 = (c42 ^ c62) & -281470681808896L;
                long c43 = c42 ^ d12;
                long c63 = c62 ^ d12;
                long d13 = (c52 ^ c72) & 72056494543077120L;
                long c53 = c52 ^ d13;
                long c73 = c72 ^ d13;
                long d14 = (c07 ^ c43) & -4294967296L;
                long c08 = c07 ^ d14;
                long c44 = c43 ^ d14;
                long d15 = (c16 ^ c53) & 72057594021150720L;
                long c17 = c16 ^ d15;
                long c54 = c53 ^ d15;
                long d16 = (c26 ^ c63) & 281474976645120L;
                long c27 = c26 ^ d16;
                long c64 = c63 ^ d16;
                long d17 = (c35 ^ c73) & 1099511627520L;
                this.internalState[0] = c08;
                this.internalState[1] = c17;
                this.internalState[2] = c27;
                this.internalState[3] = c35 ^ d17;
                this.internalState[4] = c44;
                this.internalState[5] = c54;
                this.internalState[6] = c64;
                this.internalState[7] = c73 ^ d17;
                return;
            default:
                throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
    }

    private static long mixColumn(long c) {
        long x1 = mulX(c);
        long u = rotate(8, c) ^ c;
        long u2 = (u ^ rotate(16, u)) ^ rotate(48, c);
        return ((rotate(32, mulX2((u2 ^ c) ^ x1)) ^ u2) ^ rotate(40, x1)) ^ rotate(48, x1);
    }

    private void mixColumns() {
        for (int col = 0; col < this.wordsInBlock; col++) {
            this.internalState[col] = mixColumn(this.internalState[col]);
        }
    }

    private static long mixColumnInv(long c) {
        long u0 = c ^ rotate(8, c);
        long u02 = (u0 ^ rotate(32, u0)) ^ rotate(48, c);
        long t = u02 ^ c;
        long c48 = rotate(48, c);
        long c56 = rotate(56, c);
        return u02 ^ mulX(rotate(40, ((rotate(32, t) ^ c) ^ c56) ^ mulX((((rotate(24, c) ^ t) ^ c48) ^ c56) ^ mulX(rotate(16, u02) ^ mulX((t ^ c48) ^ mulX((rotate(16, t) ^ c) ^ rotate(40, mulX(rotate(56, t) ^ mulX(t ^ c56)) ^ c)))))));
    }

    private void mixColumnsInv() {
        for (int col = 0; col < this.wordsInBlock; col++) {
            this.internalState[col] = mixColumnInv(this.internalState[col]);
        }
    }

    private static long mulX(long n) {
        return ((9187201950435737471L & n) << 1) ^ (((-9187201950435737472L & n) >>> 7) * 29);
    }

    private static long mulX2(long n) {
        return (((4557430888798830399L & n) << 2) ^ (((-9187201950435737472L & n) >>> 6) * 29)) ^ (((4629771061636907072L & n) >>> 6) * 29);
    }

    private static long rotate(int n, long x) {
        return (x >>> n) | (x << (-n));
    }

    private void rotateLeft(long[] x, long[] z) {
        switch (this.wordsInBlock) {
            case 2:
                long x0 = x[0];
                long x1 = x[1];
                z[0] = (x0 >>> 56) | (x1 << 8);
                z[1] = (x1 >>> 56) | (x0 << 8);
                return;
            case 4:
                long x02 = x[0];
                long x12 = x[1];
                long x2 = x[2];
                long x3 = x[3];
                z[0] = (x12 >>> 24) | (x2 << 40);
                z[1] = (x2 >>> 24) | (x3 << 40);
                z[2] = (x3 >>> 24) | (x02 << 40);
                z[3] = (x02 >>> 24) | (x12 << 40);
                return;
            case 8:
                long x03 = x[0];
                long x13 = x[1];
                long x22 = x[2];
                long x32 = x[3];
                long x4 = x[4];
                long x5 = x[5];
                long x6 = x[6];
                long x7 = x[7];
                z[0] = (x22 >>> 24) | (x32 << 40);
                z[1] = (x32 >>> 24) | (x4 << 40);
                z[2] = (x4 >>> 24) | (x5 << 40);
                z[3] = (x5 >>> 24) | (x6 << 40);
                z[4] = (x6 >>> 24) | (x7 << 40);
                z[5] = (x7 >>> 24) | (x03 << 40);
                z[6] = (x03 >>> 24) | (x13 << 40);
                z[7] = (x13 >>> 24) | (x22 << 40);
                return;
            default:
                throw new IllegalStateException("unsupported block length: only 128/256/512 are allowed");
        }
    }
}
