package com.mi.car.jsse.easysec.crypto.util;

import com.mi.car.jsse.easysec.asn1.ASN1Null;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.kisa.KISAObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.misc.CAST5CBCParameters;
import com.mi.car.jsse.easysec.asn1.misc.MiscObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.nist.NISTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ntt.NTTObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.oiw.OIWObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.PKCSObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.pkcs.RC2CBCParameter;
import com.mi.car.jsse.easysec.asn1.x509.AlgorithmIdentifier;
import com.mi.car.jsse.easysec.crypto.BlockCipher;
import com.mi.car.jsse.easysec.crypto.BufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.StreamCipher;
import com.mi.car.jsse.easysec.crypto.engines.AESEngine;
import com.mi.car.jsse.easysec.crypto.engines.CAST5Engine;
import com.mi.car.jsse.easysec.crypto.engines.DESEngine;
import com.mi.car.jsse.easysec.crypto.engines.DESedeEngine;
import com.mi.car.jsse.easysec.crypto.engines.RC2Engine;
import com.mi.car.jsse.easysec.crypto.engines.RC4Engine;
import com.mi.car.jsse.easysec.crypto.io.CipherOutputStream;
import com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CBCBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.CCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.modes.GCMBlockCipher;
import com.mi.car.jsse.easysec.crypto.paddings.PKCS7Padding;
import com.mi.car.jsse.easysec.crypto.paddings.PaddedBufferedBlockCipher;
import com.mi.car.jsse.easysec.crypto.params.AEADParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.params.RC2Parameters;
import com.mi.car.jsse.easysec.internal.asn1.cms.CCMParameters;
import com.mi.car.jsse.easysec.internal.asn1.cms.GCMParameters;
import java.io.OutputStream;

public class CipherFactory {
    private static final short[] rc2Ekb = {93, 190, 155, 139, 17, 153, 110, 77, 89, 243, 133, 166, 63, 183, 131, 197, 228, 115, 107, 58, 104, 90, 192, 71, 160, 100, 52, 12, 241, 208, 82, 165, 185, 30, 150, 67, 65, 216, 212, 44, 219, 248, 7, 119, 42, 202, 235, 239, 16, 28, 22, 13, 56, 114, 47, 137, 193, 249, 128, 196, 109, 174, 48, 61, 206, 32, 99, 254, 230, 26, 199, 184, 80, 232, 36, 23, 252, 37, 111, 187, 106, 163, 68, 83, 217, 162, 1, 171, 188, 182, 31, 152, 238, 154, 167, 45, 79, 158, 142, 172, 224, 198, 73, 70, 41, 244, 148, 138, 175, 225, 91, 195, 179, 123, 87, 209, 124, 156, 237, 135, 64, 140, 226, 203, 147, 20, 201, 97, 46, 229, 204, 246, 94, 168, 92, 214, 117, 141, 98, 149, 88, 105, 118, 161, 74, 181, 85, 9, 120, 51, 130, 215, 221, 121, 245, 27, 11, 222, 38, 33, 40, 116, 4, 151, 86, 223, 60, 240, 55, 57, 220, 255, 6, 164, 234, 66, 8, 218, 180, 113, 176, 207, 18, 122, 78, 250, 108, 29, 132, 0, 200, 127, 145, 69, 170, 43, 194, 177, 143, 213, 186, 242, 173, 25, 178, 103, 54, 247, 15, 10, 146, 125, 227, 157, 233, 144, 62, 35, 39, 102, 19, 236, 129, 21, 189, 34, 191, 159, 126, 169, 81, 75, 76, 251, 2, 211, 112, 134, 49, 231, 59, 5, 3, 84, 96, 72, 101, 24, 210, 205, 95, 50, 136, 14, 53, 253};

    /* JADX INFO: Multiple debug info for r3v0 com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher: [D('cipher' com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher), D('cipher' com.mi.car.jsse.easysec.crypto.StreamCipher)] */
    /* JADX INFO: Multiple debug info for r3v1 com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher: [D('cipher' com.mi.car.jsse.easysec.crypto.modes.AEADBlockCipher), D('cipher' com.mi.car.jsse.easysec.crypto.StreamCipher)] */
    /* JADX INFO: Multiple debug info for r3v2 com.mi.car.jsse.easysec.crypto.BufferedBlockCipher: [D('cipher' com.mi.car.jsse.easysec.crypto.BufferedBlockCipher), D('cipher' com.mi.car.jsse.easysec.crypto.StreamCipher)] */
    public static Object createContentCipher(boolean forEncryption, CipherParameters encKey, AlgorithmIdentifier encryptionAlgID) throws IllegalArgumentException {
        ASN1ObjectIdentifier encAlg = encryptionAlgID.getAlgorithm();
        if (encAlg.equals((ASN1Primitive) PKCSObjectIdentifiers.rc4)) {
            StreamCipher cipher = new RC4Engine();
            cipher.init(forEncryption, encKey);
            return cipher;
        } else if (encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_GCM) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_GCM) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_GCM)) {
            AEADBlockCipher cipher2 = createAEADCipher(encryptionAlgID.getAlgorithm());
            GCMParameters gcmParameters = GCMParameters.getInstance(encryptionAlgID.getParameters());
            if (!(encKey instanceof KeyParameter)) {
                throw new IllegalArgumentException("key data must be accessible for GCM operation");
            }
            cipher2.init(forEncryption, new AEADParameters((KeyParameter) encKey, gcmParameters.getIcvLen() * 8, gcmParameters.getNonce()));
            return cipher2;
        } else if (encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_CCM) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_CCM) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_CCM)) {
            AEADBlockCipher cipher3 = createAEADCipher(encryptionAlgID.getAlgorithm());
            CCMParameters ccmParameters = CCMParameters.getInstance(encryptionAlgID.getParameters());
            if (!(encKey instanceof KeyParameter)) {
                throw new IllegalArgumentException("key data must be accessible for GCM operation");
            }
            cipher3.init(forEncryption, new AEADParameters((KeyParameter) encKey, ccmParameters.getIcvLen() * 8, ccmParameters.getNonce()));
            return cipher3;
        } else {
            BufferedBlockCipher cipher4 = createCipher(encryptionAlgID.getAlgorithm());
            ASN1Primitive sParams = encryptionAlgID.getParameters().toASN1Primitive();
            if (sParams == null || (sParams instanceof ASN1Null)) {
                if (encAlg.equals((ASN1Primitive) PKCSObjectIdentifiers.des_EDE3_CBC) || encAlg.equals((ASN1Primitive) AlgorithmIdentifierFactory.IDEA_CBC) || encAlg.equals((ASN1Primitive) AlgorithmIdentifierFactory.CAST5_CBC)) {
                    cipher4.init(forEncryption, new ParametersWithIV(encKey, new byte[8]));
                    return cipher4;
                }
                cipher4.init(forEncryption, encKey);
                return cipher4;
            } else if (encAlg.equals((ASN1Primitive) PKCSObjectIdentifiers.des_EDE3_CBC) || encAlg.equals((ASN1Primitive) AlgorithmIdentifierFactory.IDEA_CBC) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes128_CBC) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes192_CBC) || encAlg.equals((ASN1Primitive) NISTObjectIdentifiers.id_aes256_CBC) || encAlg.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia128_cbc) || encAlg.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia192_cbc) || encAlg.equals((ASN1Primitive) NTTObjectIdentifiers.id_camellia256_cbc) || encAlg.equals((ASN1Primitive) KISAObjectIdentifiers.id_seedCBC) || encAlg.equals((ASN1Primitive) OIWObjectIdentifiers.desCBC)) {
                cipher4.init(forEncryption, new ParametersWithIV(encKey, ASN1OctetString.getInstance(sParams).getOctets()));
                return cipher4;
            } else if (encAlg.equals((ASN1Primitive) AlgorithmIdentifierFactory.CAST5_CBC)) {
                cipher4.init(forEncryption, new ParametersWithIV(encKey, CAST5CBCParameters.getInstance(sParams).getIV()));
                return cipher4;
            } else if (encAlg.equals((ASN1Primitive) PKCSObjectIdentifiers.RC2_CBC)) {
                RC2CBCParameter cbcParams = RC2CBCParameter.getInstance(sParams);
                cipher4.init(forEncryption, new ParametersWithIV(new RC2Parameters(((KeyParameter) encKey).getKey(), rc2Ekb[cbcParams.getRC2ParameterVersion().intValue()]), cbcParams.getIV()));
                return cipher4;
            } else {
                throw new IllegalArgumentException("cannot match parameters");
            }
        }
    }

    private static AEADBlockCipher createAEADCipher(ASN1ObjectIdentifier algorithm) {
        if (NISTObjectIdentifiers.id_aes128_GCM.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes192_GCM.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes256_GCM.equals((ASN1Primitive) algorithm)) {
            return new GCMBlockCipher(new AESEngine());
        }
        if (NISTObjectIdentifiers.id_aes128_CCM.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes192_CCM.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes256_CCM.equals((ASN1Primitive) algorithm)) {
            return new CCMBlockCipher(new AESEngine());
        }
        throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
    }

    private static BufferedBlockCipher createCipher(ASN1ObjectIdentifier algorithm) throws IllegalArgumentException {
        BlockCipher cipher;
        if (NISTObjectIdentifiers.id_aes128_CBC.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes192_CBC.equals((ASN1Primitive) algorithm) || NISTObjectIdentifiers.id_aes256_CBC.equals((ASN1Primitive) algorithm)) {
            cipher = new CBCBlockCipher(new AESEngine());
        } else if (PKCSObjectIdentifiers.des_EDE3_CBC.equals((ASN1Primitive) algorithm)) {
            cipher = new CBCBlockCipher(new DESedeEngine());
        } else if (OIWObjectIdentifiers.desCBC.equals((ASN1Primitive) algorithm)) {
            cipher = new CBCBlockCipher(new DESEngine());
        } else if (PKCSObjectIdentifiers.RC2_CBC.equals((ASN1Primitive) algorithm)) {
            cipher = new CBCBlockCipher(new RC2Engine());
        } else if (MiscObjectIdentifiers.cast5CBC.equals((ASN1Primitive) algorithm)) {
            cipher = new CBCBlockCipher(new CAST5Engine());
        } else {
            throw new IllegalArgumentException("cannot recognise cipher: " + algorithm);
        }
        return new PaddedBufferedBlockCipher(cipher, new PKCS7Padding());
    }

    public static CipherOutputStream createOutputStream(OutputStream dOut, Object cipher) {
        if (cipher instanceof BufferedBlockCipher) {
            return new CipherOutputStream(dOut, (BufferedBlockCipher) cipher);
        }
        if (cipher instanceof StreamCipher) {
            return new CipherOutputStream(dOut, (StreamCipher) cipher);
        }
        if (cipher instanceof AEADBlockCipher) {
            return new CipherOutputStream(dOut, (AEADBlockCipher) cipher);
        }
        throw new IllegalArgumentException("unknown cipher object: " + cipher);
    }
}
