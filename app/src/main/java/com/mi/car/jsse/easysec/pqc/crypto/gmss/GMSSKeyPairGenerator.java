package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPair;
import com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator;
import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.crypto.KeyGenerationParameters;
import com.mi.car.jsse.easysec.crypto.params.AsymmetricKeyParameter;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.GMSSRandom;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.WinternitzOTSVerify;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.WinternitzOTSignature;
import java.lang.reflect.Array;
import java.security.SecureRandom;
import java.util.Vector;

public class GMSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    public static final String OID = "1.3.6.1.4.1.8301.3.1.3.3";
    private int[] K;
    private byte[][] currentRootSigs;
    private byte[][] currentSeeds;
    private GMSSDigestProvider digestProvider;
    private GMSSParameters gmssPS;
    private GMSSKeyGenerationParameters gmssParams;
    private GMSSRandom gmssRandom;
    private int[] heightOfTrees;
    private boolean initialized = false;
    private int mdLength;
    private Digest messDigestTree;
    private byte[][] nextNextSeeds;
    private int numLayer;
    private int[] otsIndex;

    public GMSSKeyPairGenerator(GMSSDigestProvider digestProvider2) {
        this.digestProvider = digestProvider2;
        this.messDigestTree = digestProvider2.get();
        this.mdLength = this.messDigestTree.getDigestSize();
        this.gmssRandom = new GMSSRandom(this.messDigestTree);
    }

    private AsymmetricCipherKeyPair genKeyPair() {
        GMSSRootCalc tree;
        if (!this.initialized) {
            initializeDefault();
        }
        byte[][][] currentAuthPaths = new byte[this.numLayer][][];
        byte[][][] nextAuthPaths = new byte[(this.numLayer - 1)][][];
        Treehash[][] currentTreehash = new Treehash[this.numLayer][];
        Treehash[][] nextTreehash = new Treehash[(this.numLayer - 1)][];
        Vector[] currentStack = new Vector[this.numLayer];
        Vector[] nextStack = new Vector[(this.numLayer - 1)];
        Vector[][] currentRetain = new Vector[this.numLayer][];
        Vector[][] nextRetain = new Vector[(this.numLayer - 1)][];
        for (int i = 0; i < this.numLayer; i++) {
            currentAuthPaths[i] = (byte[][]) Array.newInstance(Byte.TYPE, this.heightOfTrees[i], this.mdLength);
            currentTreehash[i] = new Treehash[(this.heightOfTrees[i] - this.K[i])];
            if (i > 0) {
                nextAuthPaths[i - 1] = (byte[][]) Array.newInstance(Byte.TYPE, this.heightOfTrees[i], this.mdLength);
                nextTreehash[i - 1] = new Treehash[(this.heightOfTrees[i] - this.K[i])];
            }
            currentStack[i] = new Vector();
            if (i > 0) {
                nextStack[i - 1] = new Vector();
            }
        }
        byte[][] currentRoots = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer, this.mdLength);
        byte[][] nextRoots = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer - 1, this.mdLength);
        byte[][] seeds = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer, this.mdLength);
        for (int i2 = 0; i2 < this.numLayer; i2++) {
            System.arraycopy(this.currentSeeds[i2], 0, seeds[i2], 0, this.mdLength);
        }
        this.currentRootSigs = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer - 1, this.mdLength);
        for (int h = this.numLayer - 1; h >= 0; h--) {
            if (h == this.numLayer - 1) {
                tree = generateCurrentAuthpathAndRoot(null, currentStack[h], seeds[h], h);
            } else {
                tree = generateCurrentAuthpathAndRoot(currentRoots[h + 1], currentStack[h], seeds[h], h);
            }
            for (int i3 = 0; i3 < this.heightOfTrees[h]; i3++) {
                System.arraycopy(tree.getAuthPath()[i3], 0, currentAuthPaths[h][i3], 0, this.mdLength);
            }
            currentRetain[h] = tree.getRetain();
            currentTreehash[h] = tree.getTreehash();
            System.arraycopy(tree.getRoot(), 0, currentRoots[h], 0, this.mdLength);
        }
        for (int h2 = this.numLayer - 2; h2 >= 0; h2--) {
            GMSSRootCalc tree2 = generateNextAuthpathAndRoot(nextStack[h2], seeds[h2 + 1], h2 + 1);
            for (int i4 = 0; i4 < this.heightOfTrees[h2 + 1]; i4++) {
                System.arraycopy(tree2.getAuthPath()[i4], 0, nextAuthPaths[h2][i4], 0, this.mdLength);
            }
            nextRetain[h2] = tree2.getRetain();
            nextTreehash[h2] = tree2.getTreehash();
            System.arraycopy(tree2.getRoot(), 0, nextRoots[h2], 0, this.mdLength);
            System.arraycopy(seeds[h2 + 1], 0, this.nextNextSeeds[h2], 0, this.mdLength);
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new GMSSPublicKeyParameters(currentRoots[0], this.gmssPS), (AsymmetricKeyParameter) new GMSSPrivateKeyParameters(this.currentSeeds, this.nextNextSeeds, currentAuthPaths, nextAuthPaths, currentTreehash, nextTreehash, currentStack, nextStack, currentRetain, nextRetain, nextRoots, this.currentRootSigs, this.gmssPS, this.digestProvider));
    }

    private GMSSRootCalc generateCurrentAuthpathAndRoot(byte[] lowerRoot, Vector currentStack, byte[] seed, int h) {
        byte[] help;
        byte[] bArr = new byte[this.mdLength];
        byte[] bArr2 = new byte[this.mdLength];
        byte[] OTSseed = this.gmssRandom.nextSeed(seed);
        GMSSRootCalc treeToConstruct = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], this.digestProvider);
        treeToConstruct.initialize(currentStack);
        if (h == this.numLayer - 1) {
            help = new WinternitzOTSignature(OTSseed, this.digestProvider.get(), this.otsIndex[h]).getPublicKey();
        } else {
            this.currentRootSigs[h] = new WinternitzOTSignature(OTSseed, this.digestProvider.get(), this.otsIndex[h]).getSignature(lowerRoot);
            help = new WinternitzOTSVerify(this.digestProvider.get(), this.otsIndex[h]).Verify(lowerRoot, this.currentRootSigs[h]);
        }
        treeToConstruct.update(help);
        int seedForTreehashIndex = 3;
        int count = 0;
        for (int i = 1; i < (1 << this.heightOfTrees[h]); i++) {
            if (i == seedForTreehashIndex && count < this.heightOfTrees[h] - this.K[h]) {
                treeToConstruct.initializeTreehashSeed(seed, count);
                seedForTreehashIndex *= 2;
                count++;
            }
            treeToConstruct.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(seed), this.digestProvider.get(), this.otsIndex[h]).getPublicKey());
        }
        if (treeToConstruct.wasFinished()) {
            return treeToConstruct;
        }
        System.err.println("Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    private GMSSRootCalc generateNextAuthpathAndRoot(Vector nextStack, byte[] seed, int h) {
        byte[] bArr = new byte[this.numLayer];
        GMSSRootCalc treeToConstruct = new GMSSRootCalc(this.heightOfTrees[h], this.K[h], this.digestProvider);
        treeToConstruct.initialize(nextStack);
        int seedForTreehashIndex = 3;
        int count = 0;
        for (int i = 0; i < (1 << this.heightOfTrees[h]); i++) {
            if (i == seedForTreehashIndex && count < this.heightOfTrees[h] - this.K[h]) {
                treeToConstruct.initializeTreehashSeed(seed, count);
                seedForTreehashIndex *= 2;
                count++;
            }
            treeToConstruct.update(new WinternitzOTSignature(this.gmssRandom.nextSeed(seed), this.digestProvider.get(), this.otsIndex[h]).getPublicKey());
        }
        if (treeToConstruct.wasFinished()) {
            return treeToConstruct;
        }
        System.err.println("N�chster Baum noch nicht fertig konstruiert!!!");
        return null;
    }

    public void initialize(int keySize, SecureRandom secureRandom) {
        KeyGenerationParameters kgp;
        if (keySize <= 10) {
            int[] defh = {10};
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh.length, defh, new int[]{3}, new int[]{2}));
        } else if (keySize <= 20) {
            int[] defh2 = {10, 10};
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh2.length, defh2, new int[]{5, 4}, new int[]{2, 2}));
        } else {
            int[] defh3 = {10, 10, 10, 10};
            kgp = new GMSSKeyGenerationParameters(secureRandom, new GMSSParameters(defh3.length, defh3, new int[]{9, 9, 9, 3}, new int[]{2, 2, 2, 2}));
        }
        initialize(kgp);
    }

    public void initialize(KeyGenerationParameters param) {
        this.gmssParams = (GMSSKeyGenerationParameters) param;
        this.gmssPS = new GMSSParameters(this.gmssParams.getParameters().getNumOfLayers(), this.gmssParams.getParameters().getHeightOfTrees(), this.gmssParams.getParameters().getWinternitzParameter(), this.gmssParams.getParameters().getK());
        this.numLayer = this.gmssPS.getNumOfLayers();
        this.heightOfTrees = this.gmssPS.getHeightOfTrees();
        this.otsIndex = this.gmssPS.getWinternitzParameter();
        this.K = this.gmssPS.getK();
        this.currentSeeds = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer, this.mdLength);
        this.nextNextSeeds = (byte[][]) Array.newInstance(Byte.TYPE, this.numLayer - 1, this.mdLength);
        SecureRandom secRan = param.getRandom();
        for (int i = 0; i < this.numLayer; i++) {
            secRan.nextBytes(this.currentSeeds[i]);
            this.gmssRandom.nextSeed(this.currentSeeds[i]);
        }
        this.initialized = true;
    }

    private void initializeDefault() {
        int[] defh = {10, 10, 10, 10};
        initialize(new GMSSKeyGenerationParameters(null, new GMSSParameters(defh.length, defh, new int[]{3, 3, 3, 3}, new int[]{2, 2, 2, 2})));
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters param) {
        initialize(param);
    }

    @Override // com.mi.car.jsse.easysec.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }
}
