package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.NamedGroup;
import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsDecodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.util.Pack;
import java.io.IOException;

public class TlsBlockCipher implements TlsCipher {
    protected final TlsCryptoParameters cryptoParams;
    protected final byte[] randomData;
    protected final boolean encryptThenMAC;
    protected final boolean useExplicitIV;
    protected final boolean acceptExtraPadding;
    protected final boolean useExtraPadding;
    protected final TlsBlockCipherImpl decryptCipher;
    protected final TlsBlockCipherImpl encryptCipher;
    protected final TlsSuiteMac readMac;
    protected final TlsSuiteMac writeMac;

    public TlsBlockCipher(TlsCryptoParameters cryptoParams, TlsBlockCipherImpl encryptCipher, TlsBlockCipherImpl decryptCipher, TlsHMAC clientMac, TlsHMAC serverMac, int cipherKeySize) throws IOException {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (TlsImplUtils.isTLSv13(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            this.cryptoParams = cryptoParams;
            this.randomData = cryptoParams.getNonceGenerator().generateNonce(256);
            this.encryptThenMAC = securityParameters.isEncryptThenMAC();
            this.useExplicitIV = TlsImplUtils.isTLSv11(negotiatedVersion);
            this.acceptExtraPadding = !negotiatedVersion.isSSL();
            this.useExtraPadding = securityParameters.isExtendedPadding() && ProtocolVersion.TLSv10.isEqualOrEarlierVersionOf(negotiatedVersion) && (this.encryptThenMAC || !securityParameters.isTruncatedHMac());
            this.encryptCipher = encryptCipher;
            this.decryptCipher = decryptCipher;
            TlsBlockCipherImpl clientCipher;
            TlsBlockCipherImpl serverCipher;
            if (cryptoParams.isServer()) {
                clientCipher = decryptCipher;
                serverCipher = encryptCipher;
            } else {
                clientCipher = encryptCipher;
                serverCipher = decryptCipher;
            }

            int key_block_size = 2 * cipherKeySize + clientMac.getMacLength() + serverMac.getMacLength();
            if (!this.useExplicitIV) {
                key_block_size += clientCipher.getBlockSize() + serverCipher.getBlockSize();
            }

            byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);
            int offset = 0;
            clientMac.setKey(key_block, offset, clientMac.getMacLength());
            offset = offset + clientMac.getMacLength();
            serverMac.setKey(key_block, offset, serverMac.getMacLength());
            offset += serverMac.getMacLength();
            clientCipher.setKey(key_block, offset, cipherKeySize);
            offset += cipherKeySize;
            serverCipher.setKey(key_block, offset, cipherKeySize);
            offset += cipherKeySize;
            int clientIVLength = clientCipher.getBlockSize();
            int serverIVLength = serverCipher.getBlockSize();
            if (this.useExplicitIV) {
                clientCipher.init(new byte[clientIVLength], 0, clientIVLength);
                serverCipher.init(new byte[serverIVLength], 0, serverIVLength);
            } else {
                clientCipher.init(key_block, offset, clientIVLength);
                offset += clientIVLength;
                serverCipher.init(key_block, offset, serverIVLength);
                offset += serverIVLength;
            }

            if (offset != key_block_size) {
                throw new TlsFatalAlert((short)80);
            } else {
                if (cryptoParams.isServer()) {
                    this.writeMac = new TlsSuiteHMac(cryptoParams, serverMac);
                    this.readMac = new TlsSuiteHMac(cryptoParams, clientMac);
                } else {
                    this.writeMac = new TlsSuiteHMac(cryptoParams, clientMac);
                    this.readMac = new TlsSuiteHMac(cryptoParams, serverMac);
                }

            }
        }
    }

    public int getCiphertextDecodeLimit(int plaintextLimit) {
        int blockSize = this.decryptCipher.getBlockSize();
        int macSize = this.readMac.getSize();
        int maxPadding = 256;
        return this.getCiphertextLength(blockSize, macSize, maxPadding, plaintextLimit);
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) {
        int blockSize = this.encryptCipher.getBlockSize();
        int macSize = this.writeMac.getSize();
        int maxPadding = this.useExtraPadding ? 256 : blockSize;
        return this.getCiphertextLength(blockSize, macSize, maxPadding, plaintextLength);
    }

    public int getPlaintextLimit(int ciphertextLimit) {
        int blockSize = this.encryptCipher.getBlockSize();
        int macSize = this.writeMac.getSize();
        int plaintextLimit;
        if (this.encryptThenMAC) {
            plaintextLimit = ciphertextLimit - macSize;
            plaintextLimit -= plaintextLimit % blockSize;
        } else {
            plaintextLimit = ciphertextLimit - ciphertextLimit % blockSize;
            plaintextLimit -= macSize;
        }

        --plaintextLimit;
        if (this.useExplicitIV) {
            plaintextLimit -= blockSize;
        }

        return plaintextLimit;
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation, byte[] plaintext, int offset, int len) throws IOException {
        int blockSize = this.encryptCipher.getBlockSize();
        int macSize = this.writeMac.getSize();
        int enc_input_length = len;
        if (!this.encryptThenMAC) {
            enc_input_length = len + macSize;
        }

        int padding_length = blockSize - enc_input_length % blockSize;
        int totalSize;
        if (this.useExtraPadding) {
            totalSize = (256 - padding_length) / blockSize;
            int actualExtraPadBlocks = this.chooseExtraPadBlocks(totalSize);
            padding_length += actualExtraPadBlocks * blockSize;
        }

        totalSize = len + macSize + padding_length;
        if (this.useExplicitIV) {
            totalSize += blockSize;
        }

        byte[] outBuf = new byte[headerAllocation + totalSize];
        int outOff = headerAllocation;
        byte[] mac;
        if (this.useExplicitIV) {
            mac = this.cryptoParams.getNonceGenerator().generateNonce(blockSize);
            System.arraycopy(mac, 0, outBuf, headerAllocation, blockSize);
            outOff = headerAllocation + blockSize;
        }

        System.arraycopy(plaintext, offset, outBuf, outOff, len);
        outOff += len;
        if (!this.encryptThenMAC) {
            mac = this.writeMac.calculateMac(seqNo, contentType, plaintext, offset, len);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        byte padByte = (byte)(padding_length - 1);

        for(int i = 0; i < padding_length; ++i) {
            outBuf[outOff++] = padByte;
        }

        try {
            this.encryptCipher.doFinal(outBuf, headerAllocation, outOff - headerAllocation, outBuf, headerAllocation);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (this.encryptThenMAC) {
            mac = this.writeMac.calculateMac(seqNo, contentType, outBuf, headerAllocation, outOff - headerAllocation);
            System.arraycopy(mac, 0, outBuf, outOff, mac.length);
            outOff += mac.length;
        }

        if (outOff != outBuf.length) {
            throw new TlsFatalAlert((short)80);
        } else {
            return new TlsEncodeResult(outBuf, 0, outBuf.length, contentType);
        }
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int offset, int len) throws  IOException {
        int blockSize = this.decryptCipher.getBlockSize();
        int macSize = this.readMac.getSize();
        int minLen;
        if (this.encryptThenMAC) {
            minLen = blockSize + macSize;
        } else {
            minLen = Math.max(blockSize, macSize + 1);
        }

        if (this.useExplicitIV) {
            minLen += blockSize;
        }

        if (len < minLen) {
            throw new TlsFatalAlert((short)50);
        } else {
            int blocks_length = len;
            if (this.encryptThenMAC) {
                blocks_length = len - macSize;
            }

            if (blocks_length % blockSize != 0) {
                throw new TlsFatalAlert((short)21);
            } else {
                boolean badMac;
                if (this.encryptThenMAC) {
                    byte[] expectedMac = this.readMac.calculateMac(seqNo, recordType, ciphertext, offset, len - macSize);
                    badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + len - macSize);
                    if (badMac) {
                        throw new TlsFatalAlert((short)20);
                    }
                }

                try {
                    this.decryptCipher.doFinal(ciphertext, offset, blocks_length, ciphertext, offset);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (this.useExplicitIV) {
                    offset += blockSize;
                    blocks_length -= blockSize;
                }

                int totalPad = this.checkPaddingConstantTime(ciphertext, offset, blocks_length, blockSize, this.encryptThenMAC ? 0 : macSize);
                badMac = totalPad == 0;
                int dec_output_length = blocks_length - totalPad;
                if (!this.encryptThenMAC) {
                    dec_output_length -= macSize;
                    byte[] expectedMac = this.readMac.calculateMacConstantTime(seqNo, recordType, ciphertext, offset, dec_output_length, blocks_length - macSize, this.randomData);
                    badMac |= !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + dec_output_length);
                }

                if (badMac) {
                    throw new TlsFatalAlert((short)20);
                } else {
                    return new TlsDecodeResult(ciphertext, offset, dec_output_length, recordType);
                }
            }
        }
    }

    public void rekeyDecoder() throws IOException {
        throw new TlsFatalAlert((short)80);
    }

    public void rekeyEncoder() throws IOException {
        throw new TlsFatalAlert((short)80);
    }

    public boolean usesOpaqueRecordType() {
        return false;
    }

    protected int checkPaddingConstantTime(byte[] buf, int off, int len, int blockSize, int macSize) {
        int end = off + len;
        byte lastByte = buf[end - 1];
        int padlen = lastByte & 255;
        int totalPad = padlen + 1;
        int dummyIndex = 0;
        byte padDiff = 0;
        int totalPadLimit = Math.min(this.acceptExtraPadding ? 256 : blockSize, len - macSize);
        if (totalPad > totalPadLimit) {
            totalPad = 0;
        } else {
            int padPos = end - totalPad;

            do {
                padDiff = (byte)(padDiff | buf[padPos++] ^ lastByte);
            } while(padPos < end);

            dummyIndex = totalPad;
            if (padDiff != 0) {
                totalPad = 0;
            }
        }

        byte[] dummyPad;
        for(dummyPad = this.randomData; dummyIndex < 256; padDiff = (byte)(padDiff | dummyPad[dummyIndex++] ^ lastByte)) {
        }

        dummyPad[0] ^= padDiff;
        return totalPad;
    }

    protected int chooseExtraPadBlocks(int max) {
        byte[] random = this.cryptoParams.getNonceGenerator().generateNonce(4);
        int x = Pack.littleEndianToInt(random, 0);
        int n = this.lowestBitSet(x);
        return Math.min(n, max);
    }

    protected int getCiphertextLength(int blockSize, int macSize, int maxPadding, int plaintextLength) {
        int ciphertextLength = plaintextLength;
        if (this.useExplicitIV) {
            ciphertextLength = plaintextLength + blockSize;
        }

        ciphertextLength += maxPadding;
        if (this.encryptThenMAC) {
            ciphertextLength -= ciphertextLength % blockSize;
            ciphertextLength += macSize;
        } else {
            ciphertextLength += macSize;
            ciphertextLength -= ciphertextLength % blockSize;
        }

        return ciphertextLength;
    }

    protected int lowestBitSet(int x) {
        if (x == 0) {
            return 32;
        } else {
            int n;
            for(n = 0; (x & 1) == 0; x >>= 1) {
                ++n;
            }

            return n;
        }
    }
}
