//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//

package com.mi.car.jsse.easysec.jcajce.provider.symmetric.util;

import com.mi.car.jsse.easysec.crypto.CipherParameters;
import com.mi.car.jsse.easysec.crypto.PBEParametersGenerator;
import com.mi.car.jsse.easysec.crypto.digests.GOST3411Digest;
import com.mi.car.jsse.easysec.crypto.digests.MD2Digest;
import com.mi.car.jsse.easysec.crypto.digests.RIPEMD160Digest;
import com.mi.car.jsse.easysec.crypto.digests.SM3Digest;
import com.mi.car.jsse.easysec.crypto.digests.TigerDigest;
import com.mi.car.jsse.easysec.crypto.generators.OpenSSLPBEParametersGenerator;
import com.mi.car.jsse.easysec.crypto.generators.PKCS12ParametersGenerator;
import com.mi.car.jsse.easysec.crypto.generators.PKCS5S1ParametersGenerator;
import com.mi.car.jsse.easysec.crypto.generators.PKCS5S2ParametersGenerator;
import com.mi.car.jsse.easysec.crypto.params.DESParameters;
import com.mi.car.jsse.easysec.crypto.params.KeyParameter;
import com.mi.car.jsse.easysec.crypto.params.ParametersWithIV;
import com.mi.car.jsse.easysec.crypto.util.DigestFactory;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

public interface PBE {
    int MD5 = 0;
    int SHA1 = 1;
    int RIPEMD160 = 2;
    int TIGER = 3;
    int SHA256 = 4;
    int MD2 = 5;
    int GOST3411 = 6;
    int SHA224 = 7;
    int SHA384 = 8;
    int SHA512 = 9;
    int SHA3_224 = 10;
    int SHA3_256 = 11;
    int SHA3_384 = 12;
    int SHA3_512 = 13;
    int SM3 = 14;
    int PKCS5S1 = 0;
    int PKCS5S2 = 1;
    int PKCS12 = 2;
    int OPENSSL = 3;
    int PKCS5S1_UTF8 = 4;
    int PKCS5S2_UTF8 = 5;

    public static class Util {
        public Util() {
        }

        private static PBEParametersGenerator makePBEGenerator(int type, int hash) {
            Object generator;
            if (type != 0 && type != 4) {
                if (type != 1 && type != 5) {
                    if (type == 2) {
                        switch(hash) {
                            case 0:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createMD5());
                                break;
                            case 1:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createSHA1());
                                break;
                            case 2:
                                generator = new PKCS12ParametersGenerator(new RIPEMD160Digest());
                                break;
                            case 3:
                                generator = new PKCS12ParametersGenerator(new TigerDigest());
                                break;
                            case 4:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createSHA256());
                                break;
                            case 5:
                                generator = new PKCS12ParametersGenerator(new MD2Digest());
                                break;
                            case 6:
                                generator = new PKCS12ParametersGenerator(new GOST3411Digest());
                                break;
                            case 7:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createSHA224());
                                break;
                            case 8:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createSHA384());
                                break;
                            case 9:
                                generator = new PKCS12ParametersGenerator(DigestFactory.createSHA512());
                                break;
                            default:
                                throw new IllegalStateException("unknown digest scheme for PBE encryption.");
                        }
                    } else {
                        generator = new OpenSSLPBEParametersGenerator();
                    }
                } else {
                    switch(hash) {
                        case 0:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createMD5());
                            break;
                        case 1:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA1());
                            break;
                        case 2:
                            generator = new PKCS5S2ParametersGenerator(new RIPEMD160Digest());
                            break;
                        case 3:
                            generator = new PKCS5S2ParametersGenerator(new TigerDigest());
                            break;
                        case 4:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA256());
                            break;
                        case 5:
                            generator = new PKCS5S2ParametersGenerator(new MD2Digest());
                            break;
                        case 6:
                            generator = new PKCS5S2ParametersGenerator(new GOST3411Digest());
                            break;
                        case 7:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA224());
                            break;
                        case 8:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA384());
                            break;
                        case 9:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA512());
                            break;
                        case 10:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_224());
                            break;
                        case 11:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_256());
                            break;
                        case 12:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_384());
                            break;
                        case 13:
                            generator = new PKCS5S2ParametersGenerator(DigestFactory.createSHA3_512());
                            break;
                        case 14:
                            generator = new PKCS5S2ParametersGenerator(new SM3Digest());
                            break;
                        default:
                            throw new IllegalStateException("unknown digest scheme for PBE PKCS5S2 encryption.");
                    }
                }
            } else {
                switch(hash) {
                    case 0:
                        generator = new PKCS5S1ParametersGenerator(DigestFactory.createMD5());
                        break;
                    case 1:
                        generator = new PKCS5S1ParametersGenerator(DigestFactory.createSHA1());
                        break;
                    case 5:
                        generator = new PKCS5S1ParametersGenerator(new MD2Digest());
                        break;
                    default:
                        throw new IllegalStateException("PKCS5 scheme 1 only supports MD2, MD5 and SHA1.");
                }
            }

            return (PBEParametersGenerator)generator;
        }

        public static CipherParameters makePBEParameters(byte[] pbeKey, int scheme, int digest, int keySize, int ivSize, AlgorithmParameterSpec spec, String targetAlgorithm) throws InvalidAlgorithmParameterException {
            if (spec != null && spec instanceof PBEParameterSpec) {
                PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
                PBEParametersGenerator generator = makePBEGenerator(scheme, digest);
                generator.init(pbeKey, pbeParam.getSalt(), pbeParam.getIterationCount());
                CipherParameters param;
                if (ivSize != 0) {
                    param = generator.generateDerivedParameters(keySize, ivSize);
                } else {
                    param = generator.generateDerivedParameters(keySize);
                }

                if (targetAlgorithm.startsWith("DES")) {
                    KeyParameter kParam;
                    if (param instanceof ParametersWithIV) {
                        kParam = (KeyParameter)((ParametersWithIV)param).getParameters();
                        DESParameters.setOddParity(kParam.getKey());
                    } else {
                        kParam = (KeyParameter)param;
                        DESParameters.setOddParity(kParam.getKey());
                    }
                }

                return param;
            } else {
                throw new InvalidAlgorithmParameterException("Need a PBEParameter spec with a PBE key.");
            }
        }

        public static CipherParameters makePBEParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec, String targetAlgorithm) {
            if (spec != null && spec instanceof PBEParameterSpec) {
                PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
                PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
                byte[] key = pbeKey.getEncoded();
                if (pbeKey.shouldTryWrongPKCS12()) {
                    key = new byte[2];
                }

                generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
                CipherParameters param;
                if (pbeKey.getIvSize() != 0) {
                    param = generator.generateDerivedParameters(pbeKey.getKeySize(), pbeKey.getIvSize());
                } else {
                    param = generator.generateDerivedParameters(pbeKey.getKeySize());
                }

                if (targetAlgorithm.startsWith("DES")) {
                    KeyParameter kParam;
                    if (param instanceof ParametersWithIV) {
                        kParam = (KeyParameter)((ParametersWithIV)param).getParameters();
                        DESParameters.setOddParity(kParam.getKey());
                    } else {
                        kParam = (KeyParameter)param;
                        DESParameters.setOddParity(kParam.getKey());
                    }
                }

                return param;
            } else {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
        }

        public static CipherParameters makePBEMacParameters(BCPBEKey pbeKey, AlgorithmParameterSpec spec) {
            if (spec != null && spec instanceof PBEParameterSpec) {
                PBEParameterSpec pbeParam = (PBEParameterSpec)spec;
                PBEParametersGenerator generator = makePBEGenerator(pbeKey.getType(), pbeKey.getDigest());
                byte[] key = pbeKey.getEncoded();
                generator.init(key, pbeParam.getSalt(), pbeParam.getIterationCount());
                CipherParameters param = generator.generateDerivedMacParameters(pbeKey.getKeySize());
                return param;
            } else {
                throw new IllegalArgumentException("Need a PBEParameter spec with a PBE key.");
            }
        }

        public static CipherParameters makePBEMacParameters(PBEKeySpec keySpec, int type, int hash, int keySize) {
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            byte[] key = convertPassword(type, keySpec);
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
            CipherParameters param = generator.generateDerivedMacParameters(keySize);

            for(int i = 0; i != key.length; ++i) {
                key[i] = 0;
            }

            return param;
        }

        public static CipherParameters makePBEParameters(PBEKeySpec keySpec, int type, int hash, int keySize, int ivSize) {
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            byte[] key = convertPassword(type, keySpec);
            generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());
            CipherParameters param;
            if (ivSize != 0) {
                param = generator.generateDerivedParameters(keySize, ivSize);
            } else {
                param = generator.generateDerivedParameters(keySize);
            }

            for(int i = 0; i != key.length; ++i) {
                key[i] = 0;
            }

            return param;
        }

        public static CipherParameters makePBEMacParameters(SecretKey key, int type, int hash, int keySize, PBEParameterSpec pbeSpec) {
            PBEParametersGenerator generator = makePBEGenerator(type, hash);
            byte[] keyBytes = key.getEncoded();
            generator.init(key.getEncoded(), pbeSpec.getSalt(), pbeSpec.getIterationCount());
            CipherParameters param = generator.generateDerivedMacParameters(keySize);

            for(int i = 0; i != keyBytes.length; ++i) {
                keyBytes[i] = 0;
            }

            return param;
        }

        private static byte[] convertPassword(int type, PBEKeySpec keySpec) {
            byte[] key;
            if (type == 2) {
                key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
            } else if (type != 5 && type != 4) {
                key = PBEParametersGenerator.PKCS5PasswordToBytes(keySpec.getPassword());
            } else {
                key = PBEParametersGenerator.PKCS5PasswordToUTF8Bytes(keySpec.getPassword());
            }

            return key;
        }
    }
}