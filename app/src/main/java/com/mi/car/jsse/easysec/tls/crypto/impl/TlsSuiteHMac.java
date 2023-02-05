package com.mi.car.jsse.easysec.tls.crypto.impl;

import com.mi.car.jsse.easysec.tls.ProtocolVersion;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import com.mi.car.jsse.easysec.tls.crypto.TlsCryptoParameters;
import com.mi.car.jsse.easysec.tls.crypto.TlsHMAC;
import com.mi.car.jsse.easysec.tls.crypto.TlsMAC;
import com.mi.car.jsse.easysec.util.Arrays;

public class TlsSuiteHMac implements TlsSuiteMac {
    protected final TlsCryptoParameters cryptoParams;
    protected final int digestBlockSize;
    protected final int digestOverhead;
    protected final TlsHMAC mac;
    protected final int macSize;

    protected static int getMacSize(TlsCryptoParameters cryptoParams2, TlsMAC mac2) {
        int macSize2 = mac2.getMacLength();
        if (cryptoParams2.getSecurityParametersHandshake().isTruncatedHMac()) {
            return Math.min(macSize2, 10);
        }
        return macSize2;
    }

    public TlsSuiteHMac(TlsCryptoParameters cryptoParams2, TlsHMAC mac2) {
        this.cryptoParams = cryptoParams2;
        this.mac = mac2;
        this.macSize = getMacSize(cryptoParams2, mac2);
        this.digestBlockSize = mac2.getInternalBlockSize();
        if (!TlsImplUtils.isSSL(cryptoParams2) || mac2.getMacLength() != 20) {
            this.digestOverhead = this.digestBlockSize / 8;
        } else {
            this.digestOverhead = 4;
        }
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsSuiteMac
    public int getSize() {
        return this.macSize;
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsSuiteMac
    public byte[] calculateMac(long seqNo, short type, byte[] msg, int msgOff, int msgLen) {
        ProtocolVersion serverVersion = this.cryptoParams.getServerVersion();
        boolean isSSL = serverVersion.isSSL();
        byte[] macHeader = new byte[(isSSL ? 11 : 13)];
        TlsUtils.writeUint64(seqNo, macHeader, 0);
        TlsUtils.writeUint8(type, macHeader, 8);
        if (!isSSL) {
            TlsUtils.writeVersion(serverVersion, macHeader, 9);
        }
        TlsUtils.writeUint16(msgLen, macHeader, macHeader.length - 2);
        this.mac.update(macHeader, 0, macHeader.length);
        this.mac.update(msg, msgOff, msgLen);
        return truncate(this.mac.calculateMAC());
    }

    @Override // com.mi.car.jsse.easysec.tls.crypto.impl.TlsSuiteMac
    public byte[] calculateMacConstantTime(long seqNo, short type, byte[] msg, int msgOff, int msgLen, int fullLength, byte[] dummyData) {
        byte[] result = calculateMac(seqNo, type, msg, msgOff, msgLen);
        int headerLength = TlsImplUtils.isSSL(this.cryptoParams) ? 11 : 13;
        int extra = getDigestBlockCount(headerLength + fullLength) - getDigestBlockCount(headerLength + msgLen);
        while (true) {
            extra--;
            if (extra >= 0) {
                this.mac.update(dummyData, 0, this.digestBlockSize);
            } else {
                this.mac.update(dummyData, 0, 1);
                this.mac.reset();
                return result;
            }
        }
    }

    /* access modifiers changed from: protected */
    public int getDigestBlockCount(int inputLength) {
        return (this.digestOverhead + inputLength) / this.digestBlockSize;
    }

    /* access modifiers changed from: protected */
    public byte[] truncate(byte[] bs) {
        return bs.length <= this.macSize ? bs : Arrays.copyOf(bs, this.macSize);
    }
}
