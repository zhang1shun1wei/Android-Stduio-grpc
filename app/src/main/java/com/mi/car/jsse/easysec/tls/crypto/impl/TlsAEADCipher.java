package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.SecurityParameters;
import com.mi.car.jsse.easysec.tls.TlsFatalAlert;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCipher;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsDecodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsEncodeResult;
import com.mi.car.jsse.easysec.tls.crypto.TlsSecret;
import java.io.IOException;

public class TlsAEADCipher implements TlsCipher {
    public static final int AEAD_CCM = 1;
    public static final int AEAD_CHACHA20_POLY1305 = 2;
    public static final int AEAD_GCM = 3;
    private static final int NONCE_RFC5288 = 1;
    private static final int NONCE_RFC7905 = 2;
    protected final TlsCryptoParameters cryptoParams;
    protected final int keySize;
    protected final int macSize;
    protected final int fixed_iv_length;
    protected final int record_iv_length;
    protected final TlsAEADCipherImpl decryptCipher;
    protected final TlsAEADCipherImpl encryptCipher;
    protected final byte[] decryptNonce;
    protected final byte[] encryptNonce;
    protected final boolean isTLSv13;
    protected final int nonceMode;

    public TlsAEADCipher(TlsCryptoParameters cryptoParams, TlsAEADCipherImpl encryptCipher, TlsAEADCipherImpl decryptCipher, int keySize, int macSize, int aeadType) throws IOException {
        SecurityParameters securityParameters = cryptoParams.getSecurityParametersHandshake();
        ProtocolVersion negotiatedVersion = securityParameters.getNegotiatedVersion();
        if (!TlsImplUtils.isTLSv12(negotiatedVersion)) {
            throw new TlsFatalAlert((short)80);
        } else {
            this.isTLSv13 = TlsImplUtils.isTLSv13(negotiatedVersion);
            this.nonceMode = getNonceMode(this.isTLSv13, aeadType);
            switch(this.nonceMode) {
                case 1:
                    this.fixed_iv_length = 4;
                    this.record_iv_length = 8;
                    break;
                case 2:
                    this.fixed_iv_length = 12;
                    this.record_iv_length = 0;
                    break;
                default:
                    throw new TlsFatalAlert((short)80);
            }

            this.cryptoParams = cryptoParams;
            this.keySize = keySize;
            this.macSize = macSize;
            this.decryptCipher = decryptCipher;
            this.encryptCipher = encryptCipher;
            this.decryptNonce = new byte[this.fixed_iv_length];
            this.encryptNonce = new byte[this.fixed_iv_length];
            boolean isServer = cryptoParams.isServer();
            if (this.isTLSv13) {
                this.rekeyCipher(securityParameters, decryptCipher, this.decryptNonce, !isServer);
                this.rekeyCipher(securityParameters, encryptCipher, this.encryptNonce, isServer);
            } else {
                int keyBlockSize = 2 * keySize + 2 * this.fixed_iv_length;
                byte[] keyBlock = TlsImplUtils.calculateKeyBlock(cryptoParams, keyBlockSize);
                int pos = 0;
                if (isServer) {
                    decryptCipher.setKey(keyBlock, pos, keySize);
                    pos = pos + keySize;
                    encryptCipher.setKey(keyBlock, pos, keySize);
                    pos += keySize;
                    System.arraycopy(keyBlock, pos, this.decryptNonce, 0, this.fixed_iv_length);
                    pos += this.fixed_iv_length;
                    System.arraycopy(keyBlock, pos, this.encryptNonce, 0, this.fixed_iv_length);
                    pos += this.fixed_iv_length;
                } else {
                    encryptCipher.setKey(keyBlock, pos, keySize);
                    pos = pos + keySize;
                    decryptCipher.setKey(keyBlock, pos, keySize);
                    pos += keySize;
                    System.arraycopy(keyBlock, pos, this.encryptNonce, 0, this.fixed_iv_length);
                    pos += this.fixed_iv_length;
                    System.arraycopy(keyBlock, pos, this.decryptNonce, 0, this.fixed_iv_length);
                    pos += this.fixed_iv_length;
                }

                if (keyBlockSize != pos) {
                    throw new TlsFatalAlert((short)80);
                } else {
                    int nonceLength = this.fixed_iv_length + this.record_iv_length;
                    byte[] dummyNonce = new byte[nonceLength];
                    dummyNonce[0] = (byte)(~this.encryptNonce[0]);
                    dummyNonce[1] = (byte)(~this.decryptNonce[1]);
                    encryptCipher.init(dummyNonce, macSize, (byte[])null);
                    decryptCipher.init(dummyNonce, macSize, (byte[])null);
                }
            }
        }
    }

    public int getCiphertextDecodeLimit(int plaintextLimit) {
        return plaintextLimit + this.macSize + this.record_iv_length + (this.isTLSv13 ? 1 : 0);
    }

    public int getCiphertextEncodeLimit(int plaintextLength, int plaintextLimit) {
        int innerPlaintextLimit = plaintextLength;
        if (this.isTLSv13) {
            int maxPadding = 0;
            innerPlaintextLimit = 1 + Math.min(plaintextLimit, plaintextLength + maxPadding);
        }

        return innerPlaintextLimit + this.macSize + this.record_iv_length;
    }

    public int getPlaintextLimit(int ciphertextLimit) {
        return ciphertextLimit - this.macSize - this.record_iv_length - (this.isTLSv13 ? 1 : 0);
    }

    public TlsEncodeResult encodePlaintext(long seqNo, short contentType, ProtocolVersion recordVersion, int headerAllocation, byte[] plaintext, int plaintextOffset, int plaintextLength) throws IOException {
        byte[] nonce;
        int extraLength;
        nonce = new byte[this.encryptNonce.length + this.record_iv_length];
        label50:
        switch(this.nonceMode) {
            case 1:
                System.arraycopy(this.encryptNonce, 0, nonce, 0, this.encryptNonce.length);
                TlsUtils.writeUint64(seqNo, nonce, this.encryptNonce.length);
                break;
            case 2:
                TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
                extraLength = 0;

                while(true) {
                    if (extraLength >= this.encryptNonce.length) {
                        break label50;
                    }

                    nonce[extraLength] ^= this.encryptNonce[extraLength];
                    ++extraLength;
                }
            default:
                throw new TlsFatalAlert((short)80);
        }

        extraLength = this.isTLSv13 ? 1 : 0;
        int encryptionLength = this.encryptCipher.getOutputSize(plaintextLength + extraLength);
        int ciphertextLength = this.record_iv_length + encryptionLength;
        byte[] output = new byte[headerAllocation + ciphertextLength];
        int outputPos = headerAllocation;
        if (this.record_iv_length != 0) {
            System.arraycopy(nonce, nonce.length - this.record_iv_length, output, headerAllocation, this.record_iv_length);
            outputPos = headerAllocation + this.record_iv_length;
        }

        short recordType = this.isTLSv13 ? 23 : contentType;
        byte[] additionalData = this.getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength, plaintextLength);

        try {
            this.encryptCipher.init(nonce, this.macSize, additionalData);
            System.arraycopy(plaintext, plaintextOffset, output, outputPos, plaintextLength);
            if (this.isTLSv13) {
                output[outputPos + plaintextLength] = (byte)contentType;
            }

            outputPos += this.encryptCipher.doFinal(output, outputPos, plaintextLength + extraLength, output, outputPos);
        } catch (RuntimeException var18) {
            throw new TlsFatalAlert((short)80, var18);
        }

        if (outputPos != output.length) {
            throw new TlsFatalAlert((short)80);
        } else {
            return new TlsEncodeResult(output, 0, output.length, recordType);
        }
    }

    public TlsDecodeResult decodeCiphertext(long seqNo, short recordType, ProtocolVersion recordVersion, byte[] ciphertext, int ciphertextOffset, int ciphertextLength) throws IOException {
        if (this.getPlaintextLimit(ciphertextLength) < 0) {
            throw new TlsFatalAlert((short)50);
        } else {
            byte[] nonce;
            int encryptionOffset;
            nonce = new byte[this.decryptNonce.length + this.record_iv_length];
            label49:
            switch(this.nonceMode) {
                case 1:
                    System.arraycopy(this.decryptNonce, 0, nonce, 0, this.decryptNonce.length);
                    System.arraycopy(ciphertext, ciphertextOffset, nonce, nonce.length - this.record_iv_length, this.record_iv_length);
                    break;
                case 2:
                    TlsUtils.writeUint64(seqNo, nonce, nonce.length - 8);
                    encryptionOffset = 0;

                    while(true) {
                        if (encryptionOffset >= this.decryptNonce.length) {
                            break label49;
                        }

                        nonce[encryptionOffset] ^= this.decryptNonce[encryptionOffset];
                        ++encryptionOffset;
                    }
                default:
                    throw new TlsFatalAlert((short)80);
            }

            encryptionOffset = ciphertextOffset + this.record_iv_length;
            int encryptionLength = ciphertextLength - this.record_iv_length;
            int plaintextLength = this.decryptCipher.getOutputSize(encryptionLength);
            byte[] additionalData = this.getAdditionalData(seqNo, recordType, recordVersion, ciphertextLength, plaintextLength);

            int outputPos;
            try {
                this.decryptCipher.init(nonce, this.macSize, additionalData);
                outputPos = this.decryptCipher.doFinal(ciphertext, encryptionOffset, encryptionLength, ciphertext, encryptionOffset);
            } catch (RuntimeException var17) {
                throw new TlsFatalAlert((short)20, var17);
            }

            if (outputPos != plaintextLength) {
                throw new TlsFatalAlert((short)80);
            } else {
                short contentType = recordType;
                if (this.isTLSv13) {
                    int pos = plaintextLength;

                    byte octet;
                    do {
                        --pos;
                        if (pos < 0) {
                            throw new TlsFatalAlert((short)10);
                        }

                        octet = ciphertext[encryptionOffset + pos];
                    } while(0 == octet);

                    contentType = (short)(octet & 255);
                    plaintextLength = pos;
                }

                return new TlsDecodeResult(ciphertext, encryptionOffset, plaintextLength, contentType);
            }
        }
    }

    public void rekeyDecoder() throws IOException {
        this.rekeyCipher(this.cryptoParams.getSecurityParametersConnection(), this.decryptCipher, this.decryptNonce, !this.cryptoParams.isServer());
    }

    public void rekeyEncoder() throws IOException {
        this.rekeyCipher(this.cryptoParams.getSecurityParametersConnection(), this.encryptCipher, this.encryptNonce, this.cryptoParams.isServer());
    }

    public boolean usesOpaqueRecordType() {
        return this.isTLSv13;
    }

    protected byte[] getAdditionalData(long seqNo, short recordType, ProtocolVersion recordVersion, int ciphertextLength, int plaintextLength) throws IOException {
        byte[] additional_data;
        if (this.isTLSv13) {
            additional_data = new byte[5];
            TlsUtils.writeUint8(recordType, additional_data, 0);
            TlsUtils.writeVersion(recordVersion, additional_data, 1);
            TlsUtils.writeUint16(ciphertextLength, additional_data, 3);
            return additional_data;
        } else {
            additional_data = new byte[13];
            TlsUtils.writeUint64(seqNo, additional_data, 0);
            TlsUtils.writeUint8(recordType, additional_data, 8);
            TlsUtils.writeVersion(recordVersion, additional_data, 9);
            TlsUtils.writeUint16(plaintextLength, additional_data, 11);
            return additional_data;
        }
    }

    protected void rekeyCipher(SecurityParameters securityParameters, TlsAEADCipherImpl cipher, byte[] nonce, boolean serverSecret) throws IOException {
        if (!this.isTLSv13) {
            throw new TlsFatalAlert((short)80);
        } else {
            TlsSecret secret = serverSecret ? securityParameters.getTrafficSecretServer() : securityParameters.getTrafficSecretClient();
            if (null == secret) {
                throw new TlsFatalAlert((short)80);
            } else {
                this.setup13Cipher(cipher, nonce, secret, securityParameters.getPRFCryptoHashAlgorithm());
            }
        }
    }

    protected void setup13Cipher(TlsAEADCipherImpl cipher, byte[] nonce, TlsSecret secret, int cryptoHashAlgorithm) throws IOException {
        byte[] key = TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, "key", TlsUtils.EMPTY_BYTES, this.keySize).extract();
        byte[] iv = TlsCryptoUtils.hkdfExpandLabel(secret, cryptoHashAlgorithm, "iv", TlsUtils.EMPTY_BYTES, this.fixed_iv_length).extract();
        cipher.setKey(key, 0, this.keySize);
        System.arraycopy(iv, 0, nonce, 0, this.fixed_iv_length);
        iv[0] = (byte)(iv[0] ^ 128);
        cipher.init(iv, this.macSize, (byte[])null);
    }

    private static int getNonceMode(boolean isTLSv13, int aeadType) throws IOException {
        switch(aeadType) {
            case 1:
            case 3:
                return isTLSv13 ? 2 : 1;
            case 2:
                return 2;
            default:
                throw new TlsFatalAlert((short)80);
        }
    }
}
