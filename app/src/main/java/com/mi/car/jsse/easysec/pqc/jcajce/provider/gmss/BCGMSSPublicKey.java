package com.mi.car.jsse.easysec.pqc.jcajce.provider.gmss;

import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.pqc.asn1.GMSSPublicKey;
import com.mi.car.jsse.easysec.pqc.asn1.PQCObjectIdentifiers;
import com.mi.car.jsse.easysec.pqc.asn1.ParSet;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.GMSSParameters;
import com.mi.car.jsse.easysec.pqc.crypto.gmss.GMSSPublicKeyParameters;
import com.mi.car.jsse.easysec.pqc.jcajce.provider.util.KeyUtil;
import com.mi.car.jsse.easysec.util.encoders.Hex;
import java.security.PublicKey;

public class BCGMSSPublicKey implements CipherParameters, PublicKey {
    private static final long serialVersionUID = 1;
    private GMSSParameters gmssParameterSet;
    private GMSSParameters gmssParams;
    private byte[] publicKeyBytes;

    public BCGMSSPublicKey(byte[] pub, GMSSParameters gmssParameterSet2) {
        this.gmssParameterSet = gmssParameterSet2;
        this.publicKeyBytes = pub;
    }

    public BCGMSSPublicKey(GMSSPublicKeyParameters params) {
        this(params.getPublicKey(), params.getParameters());
    }

    public String getAlgorithm() {
        return "GMSS";
    }

    public byte[] getPublicKeyBytes() {
        return this.publicKeyBytes;
    }

    public GMSSParameters getParameterSet() {
        return this.gmssParameterSet;
    }

    public String toString() {
        String out = "GMSS public key : " + new String(Hex.encode(this.publicKeyBytes)) + "\nHeight of Trees: \n";
        for (int i = 0; i < this.gmssParameterSet.getHeightOfTrees().length; i++) {
            out = out + "Layer " + i + " : " + this.gmssParameterSet.getHeightOfTrees()[i] + " WinternitzParameter: " + this.gmssParameterSet.getWinternitzParameter()[i] + " K: " + this.gmssParameterSet.getK()[i] + "\n";
        }
        return out;
    }

    public byte[] getEncoded() {
        return KeyUtil.getEncodedSubjectPublicKeyInfo(new AlgorithmIdentifier(PQCObjectIdentifiers.gmss, new ParSet(this.gmssParameterSet.getNumOfLayers(), this.gmssParameterSet.getHeightOfTrees(), this.gmssParameterSet.getWinternitzParameter(), this.gmssParameterSet.getK()).toASN1Primitive()), new GMSSPublicKey(this.publicKeyBytes));
    }

    public String getFormat() {
        return "X.509";
    }
}
