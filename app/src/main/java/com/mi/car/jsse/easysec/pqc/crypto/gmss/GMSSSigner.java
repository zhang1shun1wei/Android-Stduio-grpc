package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.GMSSRandom;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.GMSSUtil;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.WinternitzOTSVerify;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.WinternitzOTSignature;
import com.mi.car.jsse.easysec.util.Arrays;
import java.lang.reflect.Array;
import java.security.SecureRandom;

public class GMSSSigner implements MessageSigner {
    private byte[][][] currentAuthPaths;
    private GMSSDigestProvider digestProvider;
    private GMSSParameters gmssPS;
    private GMSSRandom gmssRandom;
    private GMSSUtil gmssUtil = new GMSSUtil();
    private int[] index;
    GMSSKeyParameters key;
    private int mdLength;
    private Digest messDigestOTS;
    private Digest messDigestTrees;
    private int numLayer;
    private WinternitzOTSignature ots;
    private byte[] pubKeyBytes;
    private SecureRandom random;
    private byte[][] subtreeRootSig;

    public GMSSSigner(GMSSDigestProvider digest) {
        this.digestProvider = digest;
        this.messDigestTrees = digest.get();
        this.messDigestOTS = this.messDigestTrees;
        this.mdLength = this.messDigestTrees.getDigestSize();
        this.gmssRandom = new GMSSRandom(this.messDigestTrees);
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.key = (GMSSPublicKeyParameters) param;
            initVerify();
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            this.key = (GMSSPrivateKeyParameters) rParam.getParameters();
            initSign();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (GMSSPrivateKeyParameters) param;
            initSign();
        }
    }

    private void initSign() {
        this.messDigestTrees.reset();
        GMSSPrivateKeyParameters gmssPrivateKey = (GMSSPrivateKeyParameters) this.key;
        if (gmssPrivateKey.isUsed()) {
            throw new IllegalStateException("Private key already used");
        } else if (gmssPrivateKey.getIndex(0) >= gmssPrivateKey.getNumLeafs(0)) {
            throw new IllegalStateException("No more signatures can be generated");
        } else {
            this.gmssPS = gmssPrivateKey.getParameters();
            this.numLayer = this.gmssPS.getNumOfLayers();
            byte[] seed = gmssPrivateKey.getCurrentSeeds()[this.numLayer - 1];
            byte[] bArr = new byte[this.mdLength];
            byte[] dummy = new byte[this.mdLength];
            System.arraycopy(seed, 0, dummy, 0, this.mdLength);
            this.ots = new WinternitzOTSignature(this.gmssRandom.nextSeed(dummy), this.digestProvider.get(), this.gmssPS.getWinternitzParameter()[this.numLayer - 1]);
            byte[][][] helpCurrentAuthPaths = gmssPrivateKey.getCurrentAuthPaths();
            this.currentAuthPaths = new byte[this.numLayer][][];
            for (int j = 0; j < this.numLayer; j++) {
                this.currentAuthPaths[j] = (byte[][]) Array.newInstance(Byte.TYPE, helpCurrentAuthPaths[j].length, this.mdLength);
                for (int i = 0; i < helpCurrentAuthPaths[j].length; i++) {
                    System.arraycopy(helpCurrentAuthPaths[j][i], 0, this.currentAuthPaths[j][i], 0, this.mdLength);
                }
            }
            this.index = new int[this.numLayer];
            System.arraycopy(gmssPrivateKey.getIndex(), 0, this.index, 0, this.numLayer);
            this.subtreeRootSig = new byte[(this.numLayer - 1)][];
            for (int i2 = 0; i2 < this.numLayer - 1; i2++) {
                byte[] helpSubtreeRootSig = gmssPrivateKey.getSubtreeRootSig(i2);
                this.subtreeRootSig[i2] = new byte[helpSubtreeRootSig.length];
                System.arraycopy(helpSubtreeRootSig, 0, this.subtreeRootSig[i2], 0, helpSubtreeRootSig.length);
            }
            gmssPrivateKey.markUsed();
        }
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        byte[] bArr = new byte[this.mdLength];
        byte[] otsSig = this.ots.getSignature(message);
        byte[] authPathBytes = this.gmssUtil.concatenateArray(this.currentAuthPaths[this.numLayer - 1]);
        byte[] indexBytes = this.gmssUtil.intToBytesLittleEndian(this.index[this.numLayer - 1]);
        byte[] gmssSigFirstPart = new byte[(indexBytes.length + otsSig.length + authPathBytes.length)];
        System.arraycopy(indexBytes, 0, gmssSigFirstPart, 0, indexBytes.length);
        System.arraycopy(otsSig, 0, gmssSigFirstPart, indexBytes.length, otsSig.length);
        System.arraycopy(authPathBytes, 0, gmssSigFirstPart, indexBytes.length + otsSig.length, authPathBytes.length);
        byte[] gmssSigNextPart = new byte[0];
        for (int i = (this.numLayer - 1) - 1; i >= 0; i--) {
            byte[] authPathBytes2 = this.gmssUtil.concatenateArray(this.currentAuthPaths[i]);
            byte[] indexBytes2 = this.gmssUtil.intToBytesLittleEndian(this.index[i]);
            byte[] helpGmssSig = new byte[gmssSigNextPart.length];
            System.arraycopy(gmssSigNextPart, 0, helpGmssSig, 0, gmssSigNextPart.length);
            gmssSigNextPart = new byte[(helpGmssSig.length + indexBytes2.length + this.subtreeRootSig[i].length + authPathBytes2.length)];
            System.arraycopy(helpGmssSig, 0, gmssSigNextPart, 0, helpGmssSig.length);
            System.arraycopy(indexBytes2, 0, gmssSigNextPart, helpGmssSig.length, indexBytes2.length);
            System.arraycopy(this.subtreeRootSig[i], 0, gmssSigNextPart, helpGmssSig.length + indexBytes2.length, this.subtreeRootSig[i].length);
            System.arraycopy(authPathBytes2, 0, gmssSigNextPart, helpGmssSig.length + indexBytes2.length + this.subtreeRootSig[i].length, authPathBytes2.length);
        }
        byte[] gmssSig = new byte[(gmssSigFirstPart.length + gmssSigNextPart.length)];
        System.arraycopy(gmssSigFirstPart, 0, gmssSig, 0, gmssSigFirstPart.length);
        System.arraycopy(gmssSigNextPart, 0, gmssSig, gmssSigFirstPart.length, gmssSigNextPart.length);
        return gmssSig;
    }

    private void initVerify() {
        this.messDigestTrees.reset();
        GMSSPublicKeyParameters gmssPublicKey = (GMSSPublicKeyParameters) this.key;
        this.pubKeyBytes = gmssPublicKey.getPublicKey();
        this.gmssPS = gmssPublicKey.getParameters();
        this.numLayer = this.gmssPS.getNumOfLayers();
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        boolean success = false;
        this.messDigestOTS.reset();
        byte[] help = message;
        int nextEntry = 0;
        for (int j = this.numLayer - 1; j >= 0; j--) {
            WinternitzOTSVerify otsVerify = new WinternitzOTSVerify(this.digestProvider.get(), this.gmssPS.getWinternitzParameter()[j]);
            int otsSigLength = otsVerify.getSignatureLength();
            int index2 = this.gmssUtil.bytesToIntLittleEndian(signature, nextEntry);
            int nextEntry2 = nextEntry + 4;
            byte[] otsSig = new byte[otsSigLength];
            System.arraycopy(signature, nextEntry2, otsSig, 0, otsSigLength);
            nextEntry = nextEntry2 + otsSigLength;
            byte[] otsPublicKey = otsVerify.Verify(help, otsSig);
            if (otsPublicKey == null) {
                System.err.println("OTS Public Key is null in GMSSSignature.verify");
                return false;
            }
            byte[][] authPath = (byte[][]) Array.newInstance(Byte.TYPE, this.gmssPS.getHeightOfTrees()[j], this.mdLength);
            for (byte[] bArr : authPath) {
                System.arraycopy(signature, nextEntry, bArr, 0, this.mdLength);
                nextEntry += this.mdLength;
            }
            byte[] help2 = new byte[this.mdLength];
            help = otsPublicKey;
            int count = (1 << authPath.length) + index2;
            for (int i = 0; i < authPath.length; i++) {
                byte[] dest = new byte[(this.mdLength << 1)];
                if (count % 2 == 0) {
                    System.arraycopy(help, 0, dest, 0, this.mdLength);
                    System.arraycopy(authPath[i], 0, dest, this.mdLength, this.mdLength);
                    count /= 2;
                } else {
                    System.arraycopy(authPath[i], 0, dest, 0, this.mdLength);
                    System.arraycopy(help, 0, dest, this.mdLength, help.length);
                    count = (count - 1) / 2;
                }
                this.messDigestTrees.update(dest, 0, dest.length);
                help = new byte[this.messDigestTrees.getDigestSize()];
                this.messDigestTrees.doFinal(help, 0);
            }
        }
        if (Arrays.areEqual(this.pubKeyBytes, help)) {
            success = true;
        }
        return success;
    }
}
