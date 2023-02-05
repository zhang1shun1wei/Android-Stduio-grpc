package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsDecodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import java.io.IOException;

public class TlsNullCipher implements TlsCipher {
    protected final TlsCryptoParameters cryptoParams;
    protected final TlsSuiteHMac readMac;
    protected final TlsSuiteHMac writeMac;

    public TlsNullCipher(TlsCryptoParameters cryptoParams, TlsHMAC clientMac, TlsHMAC serverMac) throws IOException {
        if (TlsImplUtils.isTLSv13(cryptoParams)) {
            throw new TlsFatalAlert((short)80);
        } else {
            this.cryptoParams = cryptoParams;
            int key_block_size = clientMac.getMacLength() + serverMac.getMacLength();
            byte[] key_block = TlsImplUtils.calculateKeyBlock(cryptoParams, key_block_size);
            int offset = 0;
            clientMac.setKey(key_block, offset, clientMac.getMacLength());
            offset = offset + clientMac.getMacLength();
            serverMac.setKey(key_block, offset, serverMac.getMacLength());
            offset += serverMac.getMacLength();
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
        return plaintextLimit + this.writeMac.getSize();
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) {
        return plaintextLength + this.writeMac.getSize();
    }

    public int getPlaintextLimit(int ciphertextLimit) {
        return ciphertextLimit - this.writeMac.getSize();
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation, byte[] plaintext, int offset, int len) throws IOException {
        byte[] mac = this.writeMac.calculateMac(seqNo, contentType, plaintext, offset, len);
        byte[] ciphertext = new byte[headerAllocation + len + mac.length];
        System.arraycopy(plaintext, offset, ciphertext, headerAllocation, len);
        System.arraycopy(mac, 0, ciphertext, headerAllocation + len, mac.length);
        return new TlsEncodeResult(ciphertext, 0, ciphertext.length, contentType);
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int offset, int len) throws IOException {
        int macSize = this.readMac.getSize();
        if (len < macSize) {
            throw new TlsFatalAlert((short)50);
        } else {
            int macInputLen = len - macSize;
            byte[] expectedMac = this.readMac.calculateMac(seqNo, recordType, ciphertext, offset, macInputLen);
            boolean badMac = !TlsUtils.constantTimeAreEqual(macSize, expectedMac, 0, ciphertext, offset + macInputLen);
            if (badMac) {
                throw new TlsFatalAlert((short)20);
            } else {
                return new TlsDecodeResult(ciphertext, offset, macInputLen, recordType);
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
}
