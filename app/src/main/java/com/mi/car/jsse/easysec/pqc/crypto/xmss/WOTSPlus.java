package com.mi.car.jsse.easysec.pqc.crypto.xmss;

import com.mi.car.jsse.easysec.pqc.crypto.xmss.OTSHashAddress;
import com.mi.car.jsse.easysec.util.Arrays;
import java.util.ArrayList;
import java.util.List;

/* access modifiers changed from: package-private */
public final class WOTSPlus {
    private final KeyedHashFunctions khf;
    private final WOTSPlusParameters params;
    private byte[] publicSeed;
    private byte[] secretKeySeed;

    WOTSPlus(WOTSPlusParameters params2) {
        if (params2 == null) {
            throw new NullPointerException("params == null");
        }
        this.params = params2;
        int n = params2.getTreeDigestSize();
        this.khf = new KeyedHashFunctions(params2.getTreeDigest(), n);
        this.secretKeySeed = new byte[n];
        this.publicSeed = new byte[n];
    }

    /* access modifiers changed from: package-private */
    public void importKeys(byte[] secretKeySeed2, byte[] publicSeed2) {
        if (secretKeySeed2 == null) {
            throw new NullPointerException("secretKeySeed == null");
        } else if (secretKeySeed2.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of secretKeySeed needs to be equal to size of digest");
        } else if (publicSeed2 == null) {
            throw new NullPointerException("publicSeed == null");
        } else if (publicSeed2.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of publicSeed needs to be equal to size of digest");
        } else {
            this.secretKeySeed = secretKeySeed2;
            this.publicSeed = publicSeed2;
        }
    }

    /* access modifiers changed from: package-private */
    public WOTSPlusSignature sign(byte[] messageDigest, OTSHashAddress otsHashAddress) {
        if (messageDigest == null) {
            throw new NullPointerException("messageDigest == null");
        } else if (messageDigest.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else {
            List<Integer> baseWMessage = convertToBaseW(messageDigest, this.params.getWinternitzParameter(), this.params.getLen1());
            int checksum = 0;
            for (int i = 0; i < this.params.getLen1(); i++) {
                checksum += (this.params.getWinternitzParameter() - 1) - baseWMessage.get(i).intValue();
            }
            int checksum2 = checksum << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8));
            baseWMessage.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian((long) checksum2, (int) Math.ceil(((double) (this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter()))) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
            byte[][] signature = new byte[this.params.getLen()][];
            for (int i2 = 0; i2 < this.params.getLen(); i2++) {
                otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i2).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
                signature[i2] = chain(expandSecretKeySeed(i2), 0, baseWMessage.get(i2).intValue(), otsHashAddress);
            }
            return new WOTSPlusSignature(this.params, signature);
        }
    }

    /* access modifiers changed from: package-private */
    public WOTSPlusPublicKeyParameters getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress) {
        if (messageDigest == null) {
            throw new NullPointerException("messageDigest == null");
        } else if (messageDigest.length != this.params.getTreeDigestSize()) {
            throw new IllegalArgumentException("size of messageDigest needs to be equal to size of digest");
        } else if (signature == null) {
            throw new NullPointerException("signature == null");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else {
            List<Integer> baseWMessage = convertToBaseW(messageDigest, this.params.getWinternitzParameter(), this.params.getLen1());
            int checksum = 0;
            for (int i = 0; i < this.params.getLen1(); i++) {
                checksum += (this.params.getWinternitzParameter() - 1) - baseWMessage.get(i).intValue();
            }
            int checksum2 = checksum << (8 - ((this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter())) % 8));
            baseWMessage.addAll(convertToBaseW(XMSSUtil.toBytesBigEndian((long) checksum2, (int) Math.ceil(((double) (this.params.getLen2() * XMSSUtil.log2(this.params.getWinternitzParameter()))) / 8.0d)), this.params.getWinternitzParameter(), this.params.getLen2()));
            byte[][] publicKey = new byte[this.params.getLen()][];
            for (int i2 = 0; i2 < this.params.getLen(); i2++) {
                otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i2).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
                publicKey[i2] = chain(signature.toByteArray()[i2], baseWMessage.get(i2).intValue(), (this.params.getWinternitzParameter() - 1) - baseWMessage.get(i2).intValue(), otsHashAddress);
            }
            return new WOTSPlusPublicKeyParameters(this.params, publicKey);
        }
    }

    private byte[] chain(byte[] startHash, int startIndex, int steps, OTSHashAddress otsHashAddress) {
        int n = this.params.getTreeDigestSize();
        if (startHash == null) {
            throw new NullPointerException("startHash == null");
        } else if (startHash.length != n) {
            throw new IllegalArgumentException("startHash needs to be " + n + "bytes");
        } else if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        } else if (otsHashAddress.toByteArray() == null) {
            throw new NullPointerException("otsHashAddress byte array == null");
        } else if (startIndex + steps > this.params.getWinternitzParameter() - 1) {
            throw new IllegalArgumentException("max chain length must not be greater than w");
        } else if (steps == 0) {
            return startHash;
        } else {
            byte[] tmp = chain(startHash, startIndex, steps - 1, otsHashAddress);
            OTSHashAddress otsHashAddress2 = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(otsHashAddress.getChainAddress()).withHashAddress((startIndex + steps) - 1).withKeyAndMask(0)).build();
            byte[] key = this.khf.PRF(this.publicSeed, otsHashAddress2.toByteArray());
            byte[] bitmask = this.khf.PRF(this.publicSeed, ((OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress2.getLayerAddress())).withTreeAddress(otsHashAddress2.getTreeAddress())).withOTSAddress(otsHashAddress2.getOTSAddress()).withChainAddress(otsHashAddress2.getChainAddress()).withHashAddress(otsHashAddress2.getHashAddress()).withKeyAndMask(1)).build()).toByteArray());
            byte[] tmpMasked = new byte[n];
            for (int i = 0; i < n; i++) {
                tmpMasked[i] = (byte) (tmp[i] ^ bitmask[i]);
            }
            return this.khf.F(key, tmpMasked);
        }
    }

    private List<Integer> convertToBaseW(byte[] messageDigest, int w, int outLength) {
        if (messageDigest == null) {
            throw new NullPointerException("msg == null");
        } else if (w == 4 || w == 16) {
            int logW = XMSSUtil.log2(w);
            if (outLength > (messageDigest.length * 8) / logW) {
                throw new IllegalArgumentException("outLength too big");
            }
            ArrayList<Integer> res = new ArrayList<>();
            loop0:
            for (int i = 0; i < messageDigest.length; i++) {
                for (int j = 8 - logW; j >= 0; j -= logW) {
                    res.add(Integer.valueOf((messageDigest[i] >> j) & (w - 1)));
                    if (res.size() == outLength) {
                        break loop0;
                    }
                }
            }
            return res;
        } else {
            throw new IllegalArgumentException("w needs to be 4 or 16");
        }
    }

    /* access modifiers changed from: protected */
    public byte[] getWOTSPlusSecretKey(byte[] secretKeySeed2, OTSHashAddress otsHashAddress) {
        return this.khf.PRF(secretKeySeed2, ((OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(otsHashAddress.getOTSAddress()).build()).toByteArray());
    }

    private byte[] expandSecretKeySeed(int index) {
        if (index >= 0 && index < this.params.getLen()) {
            return this.khf.PRF(this.secretKeySeed, XMSSUtil.toBytesBigEndian((long) index, 32));
        }
        throw new IllegalArgumentException("index out of bounds");
    }

    /* access modifiers changed from: protected */
    public WOTSPlusParameters getParams() {
        return this.params;
    }

    /* access modifiers changed from: protected */
    public KeyedHashFunctions getKhf() {
        return this.khf;
    }

    /* access modifiers changed from: protected */
    public byte[] getSecretKeySeed() {
        return Arrays.clone(this.secretKeySeed);
    }

    /* access modifiers changed from: protected */
    public byte[] getPublicSeed() {
        return Arrays.clone(this.publicSeed);
    }

    /* access modifiers changed from: protected */
    public WOTSPlusPrivateKeyParameters getPrivateKey() {
        byte[][] privateKey = new byte[this.params.getLen()][];
        for (int i = 0; i < privateKey.length; i++) {
            privateKey[i] = expandSecretKeySeed(i);
        }
        return new WOTSPlusPrivateKeyParameters(this.params, privateKey);
    }

    /* access modifiers changed from: package-private */
    public WOTSPlusPublicKeyParameters getPublicKey(OTSHashAddress otsHashAddress) {
        if (otsHashAddress == null) {
            throw new NullPointerException("otsHashAddress == null");
        }
        byte[][] publicKey = new byte[this.params.getLen()][];
        for (int i = 0; i < this.params.getLen(); i++) {
            otsHashAddress = (OTSHashAddress) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) ((OTSHashAddress.Builder) new OTSHashAddress.Builder().withLayerAddress(otsHashAddress.getLayerAddress())).withTreeAddress(otsHashAddress.getTreeAddress())).withOTSAddress(otsHashAddress.getOTSAddress()).withChainAddress(i).withHashAddress(otsHashAddress.getHashAddress()).withKeyAndMask(otsHashAddress.getKeyAndMask())).build();
            publicKey[i] = chain(expandSecretKeySeed(i), 0, this.params.getWinternitzParameter() - 1, otsHashAddress);
        }
        return new WOTSPlusPublicKeyParameters(this.params, publicKey);
    }
}
