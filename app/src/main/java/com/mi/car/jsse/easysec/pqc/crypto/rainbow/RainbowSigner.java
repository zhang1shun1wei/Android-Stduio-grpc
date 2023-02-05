package com.mi.car.jsse.easysec.pqc.crypto.rainbow;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.CryptoServicesRegistrar;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithRandom;
import com.mi.car.jsse.easysec.pqc.crypto.MessageSigner;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.ComputeInField;
import com.mi.car.jsse.easysec.pqc.crypto.rainbow.util.GF2Field;
import java.security.SecureRandom;

public class RainbowSigner implements MessageSigner {
    private static final int MAXITS = 65536;
    private ComputeInField cf = new ComputeInField();
    RainbowKeyParameters key;
    private SecureRandom random;
    int signableDocumentLength;
    private short[] x;

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public void init(boolean forSigning, CipherParameters param) {
        if (!forSigning) {
            this.key = (RainbowPublicKeyParameters) param;
        } else if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom) param;
            this.random = rParam.getRandom();
            this.key = (RainbowPrivateKeyParameters) rParam.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (RainbowPrivateKeyParameters) param;
        }
        this.signableDocumentLength = this.key.getDocLength();
    }

    private short[] initSign(Layer[] layer, short[] msg) {
        short[] sArr = new short[msg.length];
        short[] Y_ = this.cf.multiplyMatrix(((RainbowPrivateKeyParameters) this.key).getInvA1(), this.cf.addVect(((RainbowPrivateKeyParameters) this.key).getB1(), msg));
        for (int i = 0; i < layer[0].getVi(); i++) {
            this.x[i] = (short) this.random.nextInt();
            this.x[i] = (short) (this.x[i] & 255);
        }
        return Y_;
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] message) {
        Layer[] layer = ((RainbowPrivateKeyParameters) this.key).getLayers();
        int numberOfLayers = layer.length;
        this.x = new short[((RainbowPrivateKeyParameters) this.key).getInvA2().length];
        byte[] S = new byte[layer[numberOfLayers - 1].getViNext()];
        short[] msgHashVals = makeMessageRepresentative(message);
        int itCount = 0;
        do {
            boolean ok = true;
            int counter = 0;
            try {
                short[] Y_ = initSign(layer, msgHashVals);
                for (int i = 0; i < numberOfLayers; i++) {
                    short[] y_i = new short[layer[i].getOi()];
                    short[] sArr = new short[layer[i].getOi()];
                    for (int k = 0; k < layer[i].getOi(); k++) {
                        y_i[k] = Y_[counter];
                        counter++;
                    }
                    short[] solVec = this.cf.solveEquation(layer[i].plugInVinegars(this.x), y_i);
                    if (solVec == null) {
                        throw new Exception("LES is not solveable!");
                    }
                    for (int j = 0; j < solVec.length; j++) {
                        this.x[layer[i].getVi() + j] = solVec[j];
                    }
                }
                short[] signature = this.cf.multiplyMatrix(((RainbowPrivateKeyParameters) this.key).getInvA2(), this.cf.addVect(((RainbowPrivateKeyParameters) this.key).getB2(), this.x));
                for (int i2 = 0; i2 < S.length; i2++) {
                    S[i2] = (byte) signature[i2];
                }
            } catch (Exception e) {
                ok = false;
            }
            if (ok) {
                break;
            }
            itCount++;
        } while (itCount < MAXITS);
        if (itCount != MAXITS) {
            return S;
        }
        throw new IllegalStateException("unable to generate signature - LES not solvable");
    }

    @Override // com.mi.car.jsse.easysec.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] message, byte[] signature) {
        short[] sigInt = new short[signature.length];
        for (int i = 0; i < signature.length; i++) {
            sigInt[i] = (short) (((short) signature[i]) & 255);
        }
        short[] msgHashVal = makeMessageRepresentative(message);
        short[] verificationResult = verifySignatureIntern(sigInt);
        boolean verified = true;
        if (msgHashVal.length != verificationResult.length) {
            return false;
        }
        for (int i2 = 0; i2 < msgHashVal.length; i2++) {
            verified = verified && msgHashVal[i2] == verificationResult[i2];
        }
        return verified;
    }

    private short[] verifySignatureIntern(short[] signature) {
        short[][] coeff_quadratic = ((RainbowPublicKeyParameters) this.key).getCoeffQuadratic();
        short[][] coeff_singular = ((RainbowPublicKeyParameters) this.key).getCoeffSingular();
        short[] coeff_scalar = ((RainbowPublicKeyParameters) this.key).getCoeffScalar();
        short[] rslt = new short[coeff_quadratic.length];
        int n = coeff_singular[0].length;
        for (int p = 0; p < coeff_quadratic.length; p++) {
            int offset = 0;
            for (int x2 = 0; x2 < n; x2++) {
                for (int y = x2; y < n; y++) {
                    rslt[p] = GF2Field.addElem(rslt[p], GF2Field.multElem(coeff_quadratic[p][offset], GF2Field.multElem(signature[x2], signature[y])));
                    offset++;
                }
                rslt[p] = GF2Field.addElem(rslt[p], GF2Field.multElem(coeff_singular[p][x2], signature[x2]));
            }
            rslt[p] = GF2Field.addElem(rslt[p], coeff_scalar[p]);
        }
        return rslt;
    }

    private short[] makeMessageRepresentative(byte[] message) {
        short[] output = new short[this.signableDocumentLength];
        int h = 0;
        int i = 0;
        while (i < message.length) {
            output[i] = (short) message[h];
            output[i] = (short) (output[i] & 255);
            h++;
            i++;
            if (i >= output.length) {
                break;
            }
        }
        return output;
    }
}
