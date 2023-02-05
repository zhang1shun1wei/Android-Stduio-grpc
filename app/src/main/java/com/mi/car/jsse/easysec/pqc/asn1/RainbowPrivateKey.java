package com.mi.car.jsse.easysec.pqc.asn1;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1Integer;
import com.mi.car.jsse.easysec.asn1.ASN1Object;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DEROctetString;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.Layer;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.RainbowUtil;

public class RainbowPrivateKey extends ASN1Object {
    private byte[] b1;
    private byte[] b2;
    private byte[][] invA1;
    private byte[][] invA2;
    private Layer[] layers;
    private ASN1ObjectIdentifier oid;
    private ASN1Integer version;
    private byte[] vi;

    private RainbowPrivateKey(ASN1Sequence seq) {
        if (seq.getObjectAt(0) instanceof ASN1Integer) {
            this.version = ASN1Integer.getInstance(seq.getObjectAt(0));
        } else {
            this.oid = ASN1ObjectIdentifier.getInstance(seq.getObjectAt(0));
        }
        ASN1Sequence asnA1 = (ASN1Sequence) seq.getObjectAt(1);
        this.invA1 = new byte[asnA1.size()][];
        for (int i = 0; i < asnA1.size(); i++) {
            this.invA1[i] = ((ASN1OctetString) asnA1.getObjectAt(i)).getOctets();
        }
        this.b1 = ((ASN1OctetString) ((ASN1Sequence) seq.getObjectAt(2)).getObjectAt(0)).getOctets();
        ASN1Sequence asnA2 = (ASN1Sequence) seq.getObjectAt(3);
        this.invA2 = new byte[asnA2.size()][];
        for (int j = 0; j < asnA2.size(); j++) {
            this.invA2[j] = ((ASN1OctetString) asnA2.getObjectAt(j)).getOctets();
        }
        this.b2 = ((ASN1OctetString) ((ASN1Sequence) seq.getObjectAt(4)).getObjectAt(0)).getOctets();
        this.vi = ((ASN1OctetString) ((ASN1Sequence) seq.getObjectAt(5)).getObjectAt(0)).getOctets();
        ASN1Sequence asnLayers = (ASN1Sequence) seq.getObjectAt(6);
        byte[][][][] alphas = new byte[asnLayers.size()][][][];
        byte[][][][] betas = new byte[asnLayers.size()][][][];
        byte[][][] gammas = new byte[asnLayers.size()][][];
        byte[][] etas = new byte[asnLayers.size()][];
        for (int l = 0; l < asnLayers.size(); l++) {
            ASN1Sequence asnLayer = (ASN1Sequence) asnLayers.getObjectAt(l);
            ASN1Sequence alphas3d = (ASN1Sequence) asnLayer.getObjectAt(0);
            alphas[l] = new byte[alphas3d.size()][][];
            for (int m = 0; m < alphas3d.size(); m++) {
                ASN1Sequence alphas2d = (ASN1Sequence) alphas3d.getObjectAt(m);
                alphas[l][m] = new byte[alphas2d.size()][];
                for (int n = 0; n < alphas2d.size(); n++) {
                    alphas[l][m][n] = ((ASN1OctetString) alphas2d.getObjectAt(n)).getOctets();
                }
            }
            ASN1Sequence betas3d = (ASN1Sequence) asnLayer.getObjectAt(1);
            betas[l] = new byte[betas3d.size()][][];
            for (int mb = 0; mb < betas3d.size(); mb++) {
                ASN1Sequence betas2d = (ASN1Sequence) betas3d.getObjectAt(mb);
                betas[l][mb] = new byte[betas2d.size()][];
                for (int nb = 0; nb < betas2d.size(); nb++) {
                    betas[l][mb][nb] = ((ASN1OctetString) betas2d.getObjectAt(nb)).getOctets();
                }
            }
            ASN1Sequence gammas2d = (ASN1Sequence) asnLayer.getObjectAt(2);
            gammas[l] = new byte[gammas2d.size()][];
            for (int mg = 0; mg < gammas2d.size(); mg++) {
                gammas[l][mg] = ((ASN1OctetString) gammas2d.getObjectAt(mg)).getOctets();
            }
            etas[l] = ((ASN1OctetString) asnLayer.getObjectAt(3)).getOctets();
        }
        int numOfLayers = this.vi.length - 1;
        this.layers = new Layer[numOfLayers];
        for (int i2 = 0; i2 < numOfLayers; i2++) {
            this.layers[i2] = new Layer(this.vi[i2], this.vi[i2 + 1], RainbowUtil.convertArray(alphas[i2]), RainbowUtil.convertArray(betas[i2]), RainbowUtil.convertArray(gammas[i2]), RainbowUtil.convertArray(etas[i2]));
        }
    }

    public RainbowPrivateKey(short[][] invA12, short[] b12, short[][] invA22, short[] b22, int[] vi2, Layer[] layers2) {
        this.version = new ASN1Integer(1);
        this.invA1 = RainbowUtil.convertArray(invA12);
        this.b1 = RainbowUtil.convertArray(b12);
        this.invA2 = RainbowUtil.convertArray(invA22);
        this.b2 = RainbowUtil.convertArray(b22);
        this.vi = RainbowUtil.convertIntArray(vi2);
        this.layers = layers2;
    }

    public static RainbowPrivateKey getInstance(Object o) {
        if (o instanceof RainbowPrivateKey) {
            return (RainbowPrivateKey) o;
        }
        if (o != null) {
            return new RainbowPrivateKey(ASN1Sequence.getInstance(o));
        }
        return null;
    }

    public ASN1Integer getVersion() {
        return this.version;
    }

    public short[][] getInvA1() {
        return RainbowUtil.convertArray(this.invA1);
    }

    public short[] getB1() {
        return RainbowUtil.convertArray(this.b1);
    }

    public short[] getB2() {
        return RainbowUtil.convertArray(this.b2);
    }

    public short[][] getInvA2() {
        return RainbowUtil.convertArray(this.invA2);
    }

    public Layer[] getLayers() {
        return this.layers;
    }

    public int[] getVi() {
        return RainbowUtil.convertArraytoInt(this.vi);
    }

    @Override // com.mi.car.jsse.easysec.asn1.ASN1Object, com.mi.car.jsse.easysec.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();
        if (this.version != null) {
            v.add(this.version);
        } else {
            v.add(this.oid);
        }
        ASN1EncodableVector asnA1 = new ASN1EncodableVector();
        for (int i = 0; i < this.invA1.length; i++) {
            asnA1.add(new DEROctetString(this.invA1[i]));
        }
        v.add(new DERSequence(asnA1));
        ASN1EncodableVector asnb1 = new ASN1EncodableVector();
        asnb1.add(new DEROctetString(this.b1));
        v.add(new DERSequence(asnb1));
        ASN1EncodableVector asnA2 = new ASN1EncodableVector();
        for (int i2 = 0; i2 < this.invA2.length; i2++) {
            asnA2.add(new DEROctetString(this.invA2[i2]));
        }
        v.add(new DERSequence(asnA2));
        ASN1EncodableVector asnb2 = new ASN1EncodableVector();
        asnb2.add(new DEROctetString(this.b2));
        v.add(new DERSequence(asnb2));
        ASN1EncodableVector asnvi = new ASN1EncodableVector();
        asnvi.add(new DEROctetString(this.vi));
        v.add(new DERSequence(asnvi));
        ASN1EncodableVector asnLayers = new ASN1EncodableVector();
        for (int l = 0; l < this.layers.length; l++) {
            ASN1EncodableVector aLayer = new ASN1EncodableVector();
            byte[][][] alphas = RainbowUtil.convertArray(this.layers[l].getCoeffAlpha());
            ASN1EncodableVector alphas3d = new ASN1EncodableVector();
            for (int i3 = 0; i3 < alphas.length; i3++) {
                ASN1EncodableVector alphas2d = new ASN1EncodableVector();
                for (int j = 0; j < alphas[i3].length; j++) {
                    alphas2d.add(new DEROctetString(alphas[i3][j]));
                }
                alphas3d.add(new DERSequence(alphas2d));
            }
            aLayer.add(new DERSequence(alphas3d));
            byte[][][] betas = RainbowUtil.convertArray(this.layers[l].getCoeffBeta());
            ASN1EncodableVector betas3d = new ASN1EncodableVector();
            for (int i4 = 0; i4 < betas.length; i4++) {
                ASN1EncodableVector betas2d = new ASN1EncodableVector();
                for (int j2 = 0; j2 < betas[i4].length; j2++) {
                    betas2d.add(new DEROctetString(betas[i4][j2]));
                }
                betas3d.add(new DERSequence(betas2d));
            }
            aLayer.add(new DERSequence(betas3d));
            byte[][] gammas = RainbowUtil.convertArray(this.layers[l].getCoeffGamma());
            ASN1EncodableVector asnG = new ASN1EncodableVector();
            for (int i5 = 0; i5 < gammas.length; i5++) {
                asnG.add(new DEROctetString(gammas[i5]));
            }
            aLayer.add(new DERSequence(asnG));
            aLayer.add(new DEROctetString(RainbowUtil.convertArray(this.layers[l].getCoeffEta())));
            asnLayers.add(new DERSequence(aLayer));
        }
        v.add(new DERSequence(asnLayers));
        return new DERSequence(v);
    }
}
