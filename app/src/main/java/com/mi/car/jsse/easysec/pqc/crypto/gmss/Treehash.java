package com.mi.car.jsse.easysec.pqc.crypto.gmss;

import com.mi.car.jsse.easysec.crypto.Digest;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.util.GMSSRandom;
import com.mi.car.jsse.easysec.util.Integers;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.lang.reflect.Array;
import java.util.Vector;

public class Treehash {
    private byte[] firstNode;
    private int firstNodeHeight;
    private Vector heightOfNodes;
    private boolean isFinished;
    private boolean isInitialized;
    private int maxHeight;
    private Digest messDigestTree;
    private byte[] seedActive;
    private boolean seedInitialized;
    private byte[] seedNext;
    private int tailLength;
    private Vector tailStack;

    public Treehash(Digest name, byte[][] statByte, int[] statInt) {
        this.messDigestTree = name;
        this.maxHeight = statInt[0];
        this.tailLength = statInt[1];
        this.firstNodeHeight = statInt[2];
        if (statInt[3] == 1) {
            this.isFinished = true;
        } else {
            this.isFinished = false;
        }
        if (statInt[4] == 1) {
            this.isInitialized = true;
        } else {
            this.isInitialized = false;
        }
        if (statInt[5] == 1) {
            this.seedInitialized = true;
        } else {
            this.seedInitialized = false;
        }
        this.heightOfNodes = new Vector();
        for (int i = 0; i < this.tailLength; i++) {
            this.heightOfNodes.addElement(Integers.valueOf(statInt[i + 6]));
        }
        this.firstNode = statByte[0];
        this.seedActive = statByte[1];
        this.seedNext = statByte[2];
        this.tailStack = new Vector();
        for (int i2 = 0; i2 < this.tailLength; i2++) {
            this.tailStack.addElement(statByte[i2 + 3]);
        }
    }

    public Treehash(Vector tailStack2, int maxHeight2, Digest digest) {
        this.tailStack = tailStack2;
        this.maxHeight = maxHeight2;
        this.firstNode = null;
        this.isInitialized = false;
        this.isFinished = false;
        this.seedInitialized = false;
        this.messDigestTree = digest;
        this.seedNext = new byte[this.messDigestTree.getDigestSize()];
        this.seedActive = new byte[this.messDigestTree.getDigestSize()];
    }

    public void initializeSeed(byte[] seedIn) {
        System.arraycopy(seedIn, 0, this.seedNext, 0, this.messDigestTree.getDigestSize());
        this.seedInitialized = true;
    }

    public void initialize() {
        if (!this.seedInitialized) {
            throw new IllegalStateException("Seed " + this.maxHeight + " not initialized");
        }
        this.heightOfNodes = new Vector();
        this.tailLength = 0;
        this.firstNode = null;
        this.firstNodeHeight = -1;
        this.isInitialized = true;
        System.arraycopy(this.seedNext, 0, this.seedActive, 0, this.messDigestTree.getDigestSize());
    }

    public void update(GMSSRandom gmssRandom, byte[] leaf) {
        if (this.isFinished) {
            System.err.println("No more update possible for treehash instance!");
        } else if (!this.isInitialized) {
            System.err.println("Treehash instance not initialized before update");
        } else {
            byte[] bArr = new byte[this.messDigestTree.getDigestSize()];
            gmssRandom.nextSeed(this.seedActive);
            if (this.firstNode == null) {
                this.firstNode = leaf;
                this.firstNodeHeight = 0;
            } else {
                byte[] help = leaf;
                int helpHeight = 0;
                while (this.tailLength > 0 && helpHeight == ((Integer) this.heightOfNodes.lastElement()).intValue()) {
                    byte[] toBeHashed = new byte[(this.messDigestTree.getDigestSize() << 1)];
                    System.arraycopy(this.tailStack.lastElement(), 0, toBeHashed, 0, this.messDigestTree.getDigestSize());
                    this.tailStack.removeElementAt(this.tailStack.size() - 1);
                    this.heightOfNodes.removeElementAt(this.heightOfNodes.size() - 1);
                    System.arraycopy(help, 0, toBeHashed, this.messDigestTree.getDigestSize(), this.messDigestTree.getDigestSize());
                    this.messDigestTree.update(toBeHashed, 0, toBeHashed.length);
                    help = new byte[this.messDigestTree.getDigestSize()];
                    this.messDigestTree.doFinal(help, 0);
                    helpHeight++;
                    this.tailLength--;
                }
                this.tailStack.addElement(help);
                this.heightOfNodes.addElement(Integers.valueOf(helpHeight));
                this.tailLength++;
                if (((Integer) this.heightOfNodes.lastElement()).intValue() == this.firstNodeHeight) {
                    byte[] toBeHashed2 = new byte[(this.messDigestTree.getDigestSize() << 1)];
                    System.arraycopy(this.firstNode, 0, toBeHashed2, 0, this.messDigestTree.getDigestSize());
                    System.arraycopy(this.tailStack.lastElement(), 0, toBeHashed2, this.messDigestTree.getDigestSize(), this.messDigestTree.getDigestSize());
                    this.tailStack.removeElementAt(this.tailStack.size() - 1);
                    this.heightOfNodes.removeElementAt(this.heightOfNodes.size() - 1);
                    this.messDigestTree.update(toBeHashed2, 0, toBeHashed2.length);
                    this.firstNode = new byte[this.messDigestTree.getDigestSize()];
                    this.messDigestTree.doFinal(this.firstNode, 0);
                    this.firstNodeHeight++;
                    this.tailLength = 0;
                }
            }
            if (this.firstNodeHeight == this.maxHeight) {
                this.isFinished = true;
            }
        }
    }

    public void destroy() {
        this.isInitialized = false;
        this.isFinished = false;
        this.firstNode = null;
        this.tailLength = 0;
        this.firstNodeHeight = -1;
    }

    public int getLowestNodeHeight() {
        if (this.firstNode == null) {
            return this.maxHeight;
        }
        if (this.tailLength == 0) {
            return this.firstNodeHeight;
        }
        return Math.min(this.firstNodeHeight, ((Integer) this.heightOfNodes.lastElement()).intValue());
    }

    public int getFirstNodeHeight() {
        if (this.firstNode == null) {
            return this.maxHeight;
        }
        return this.firstNodeHeight;
    }

    public boolean wasInitialized() {
        return this.isInitialized;
    }

    public boolean wasFinished() {
        return this.isFinished;
    }

    public byte[] getFirstNode() {
        return this.firstNode;
    }

    public byte[] getSeedActive() {
        return this.seedActive;
    }

    public void setFirstNode(byte[] hash) {
        if (!this.isInitialized) {
            initialize();
        }
        this.firstNode = hash;
        this.firstNodeHeight = this.maxHeight;
        this.isFinished = true;
    }

    public void updateNextSeed(GMSSRandom gmssRandom) {
        gmssRandom.nextSeed(this.seedNext);
    }

    public Vector getTailStack() {
        return this.tailStack;
    }

    public byte[][] getStatByte() {
        byte[][] statByte = (byte[][]) Array.newInstance(Byte.TYPE, this.tailLength + 3, this.messDigestTree.getDigestSize());
        statByte[0] = this.firstNode;
        statByte[1] = this.seedActive;
        statByte[2] = this.seedNext;
        for (int i = 0; i < this.tailLength; i++) {
            statByte[i + 3] = (byte[]) this.tailStack.elementAt(i);
        }
        return statByte;
    }

    public int[] getStatInt() {
        int[] statInt = new int[(this.tailLength + 6)];
        statInt[0] = this.maxHeight;
        statInt[1] = this.tailLength;
        statInt[2] = this.firstNodeHeight;
        if (this.isFinished) {
            statInt[3] = 1;
        } else {
            statInt[3] = 0;
        }
        if (this.isInitialized) {
            statInt[4] = 1;
        } else {
            statInt[4] = 0;
        }
        if (this.seedInitialized) {
            statInt[5] = 1;
        } else {
            statInt[5] = 0;
        }
        for (int i = 0; i < this.tailLength; i++) {
            statInt[i + 6] = ((Integer) this.heightOfNodes.elementAt(i)).intValue();
        }
        return statInt;
    }

    public String toString() {
        String out = "Treehash    : ";
        for (int i = 0; i < this.tailLength + 6; i++) {
            out = out + getStatInt()[i] + " ";
        }
        for (int i2 = 0; i2 < this.tailLength + 3; i2++) {
            out = getStatByte()[i2] != null ? out + new String(Hex.encode(getStatByte()[i2])) + " " : out + "null ";
        }
        return out + "  " + this.messDigestTree.getDigestSize();
    }
}
