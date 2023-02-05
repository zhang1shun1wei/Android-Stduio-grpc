package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.Key;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

abstract class JsseUtils_7 extends JsseUtils {
    static final Set<CryptoPrimitive> KEY_AGREEMENT_CRYPTO_PRIMITIVES;
    static final Set<CryptoPrimitive> KEY_ENCAPSULATION_CRYPTO_PRIMITIVES;
    static final Set<CryptoPrimitive> SIGNATURE_CRYPTO_PRIMITIVES;
    static final AlgorithmConstraints DEFAULT_ALGORITHM_CONSTRAINTS;

    JsseUtils_7() {
    }

    static AlgorithmConstraints exportAlgorithmConstraints(BCAlgorithmConstraints constraints) {
        if (ProvAlgorithmConstraints.DEFAULT == constraints) {
            return DEFAULT_ALGORITHM_CONSTRAINTS;
        } else if (constraints == null) {
            return null;
        } else {
            return (AlgorithmConstraints)(constraints instanceof JsseUtils_7.ImportAlgorithmConstraints ? ((JsseUtils_7.ImportAlgorithmConstraints)constraints).unwrap() : new JsseUtils_7.ExportAlgorithmConstraints(constraints));
        }
    }

    static Object exportAlgorithmConstraintsDynamic(BCAlgorithmConstraints constraints) {
        return exportAlgorithmConstraints(constraints);
    }

    static CryptoPrimitive exportCryptoPrimitive(BCCryptoPrimitive primitive) {
        switch(primitive) {
            case MESSAGE_DIGEST:
                return CryptoPrimitive.MESSAGE_DIGEST;
            case SECURE_RANDOM:
                return CryptoPrimitive.SECURE_RANDOM;
            case BLOCK_CIPHER:
                return CryptoPrimitive.BLOCK_CIPHER;
            case STREAM_CIPHER:
                return CryptoPrimitive.STREAM_CIPHER;
            case MAC:
                return CryptoPrimitive.MAC;
            case KEY_WRAP:
                return CryptoPrimitive.KEY_WRAP;
            case PUBLIC_KEY_ENCRYPTION:
                return CryptoPrimitive.PUBLIC_KEY_ENCRYPTION;
            case SIGNATURE:
                return CryptoPrimitive.SIGNATURE;
            case KEY_ENCAPSULATION:
                return CryptoPrimitive.KEY_ENCAPSULATION;
            case KEY_AGREEMENT:
                return CryptoPrimitive.KEY_AGREEMENT;
            default:
                return null;
        }
    }

    static Set<CryptoPrimitive> exportCryptoPrimitives(Set<BCCryptoPrimitive> primitives) {
        if (SIGNATURE_CRYPTO_PRIMITIVES_BC == primitives) {
            return SIGNATURE_CRYPTO_PRIMITIVES;
        } else if (KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC == primitives) {
            return KEY_AGREEMENT_CRYPTO_PRIMITIVES;
        } else if (KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC == primitives) {
            return KEY_ENCAPSULATION_CRYPTO_PRIMITIVES;
        } else {
            HashSet<CryptoPrimitive> result = new HashSet();
            Iterator var2 = primitives.iterator();

            while(var2.hasNext()) {
                BCCryptoPrimitive primitive = (BCCryptoPrimitive)var2.next();
                result.add(exportCryptoPrimitive(primitive));
            }

            return result;
        }
    }

    static BCAlgorithmConstraints importAlgorithmConstraints(AlgorithmConstraints constraints) {
        if (null == constraints) {
            return null;
        } else {
            return (BCAlgorithmConstraints)(constraints instanceof JsseUtils_7.ExportAlgorithmConstraints ? ((JsseUtils_7.ExportAlgorithmConstraints)constraints).unwrap() : new JsseUtils_7.ImportAlgorithmConstraints(constraints));
        }
    }

    static BCAlgorithmConstraints importAlgorithmConstraintsDynamic(Object constraints) {
        return importAlgorithmConstraints((AlgorithmConstraints)constraints);
    }

    static BCCryptoPrimitive importCryptoPrimitive(CryptoPrimitive primitive) {
        switch(primitive) {
            case MESSAGE_DIGEST:
                return BCCryptoPrimitive.MESSAGE_DIGEST;
            case SECURE_RANDOM:
                return BCCryptoPrimitive.SECURE_RANDOM;
            case BLOCK_CIPHER:
                return BCCryptoPrimitive.BLOCK_CIPHER;
            case STREAM_CIPHER:
                return BCCryptoPrimitive.STREAM_CIPHER;
            case MAC:
                return BCCryptoPrimitive.MAC;
            case KEY_WRAP:
                return BCCryptoPrimitive.KEY_WRAP;
            case PUBLIC_KEY_ENCRYPTION:
                return BCCryptoPrimitive.PUBLIC_KEY_ENCRYPTION;
            case SIGNATURE:
                return BCCryptoPrimitive.SIGNATURE;
            case KEY_ENCAPSULATION:
                return BCCryptoPrimitive.KEY_ENCAPSULATION;
            case KEY_AGREEMENT:
                return BCCryptoPrimitive.KEY_AGREEMENT;
            default:
                return null;
        }
    }

    static Set<BCCryptoPrimitive> importCryptoPrimitives(Set<CryptoPrimitive> primitives) {
        if (SIGNATURE_CRYPTO_PRIMITIVES == primitives) {
            return SIGNATURE_CRYPTO_PRIMITIVES_BC;
        } else if (KEY_AGREEMENT_CRYPTO_PRIMITIVES == primitives) {
            return KEY_AGREEMENT_CRYPTO_PRIMITIVES_BC;
        } else if (KEY_ENCAPSULATION_CRYPTO_PRIMITIVES == primitives) {
            return KEY_ENCAPSULATION_CRYPTO_PRIMITIVES_BC;
        } else {
            HashSet<BCCryptoPrimitive> result = new HashSet();
            Iterator var2 = primitives.iterator();

            while(var2.hasNext()) {
                CryptoPrimitive primitive = (CryptoPrimitive)var2.next();
                result.add(importCryptoPrimitive(primitive));
            }

            return result;
        }
    }

    static {
        KEY_AGREEMENT_CRYPTO_PRIMITIVES = Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.KEY_AGREEMENT));
        KEY_ENCAPSULATION_CRYPTO_PRIMITIVES = Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.KEY_ENCAPSULATION));
        SIGNATURE_CRYPTO_PRIMITIVES = Collections.unmodifiableSet(EnumSet.of(CryptoPrimitive.SIGNATURE));
        DEFAULT_ALGORITHM_CONSTRAINTS = new JsseUtils_7.ExportAlgorithmConstraints(ProvAlgorithmConstraints.DEFAULT);
    }

    static class ImportAlgorithmConstraints implements BCAlgorithmConstraints {
        private final AlgorithmConstraints constraints;

        ImportAlgorithmConstraints(AlgorithmConstraints constraints) {
            this.constraints = constraints;
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, Key key) {
            return this.constraints.permits(JsseUtils_7.exportCryptoPrimitives(primitives), key);
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
            return this.constraints.permits(JsseUtils_7.exportCryptoPrimitives(primitives), algorithm, parameters);
        }

        public boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
            return this.constraints.permits(JsseUtils_7.exportCryptoPrimitives(primitives), algorithm, key, parameters);
        }

        AlgorithmConstraints unwrap() {
            return this.constraints;
        }
    }

    static class ExportAlgorithmConstraints implements AlgorithmConstraints {
        private final BCAlgorithmConstraints constraints;

        ExportAlgorithmConstraints(BCAlgorithmConstraints constraints) {
            this.constraints = constraints;
        }

        public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
            return this.constraints.permits(JsseUtils_7.importCryptoPrimitives(primitives), key);
        }

        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
            return this.constraints.permits(JsseUtils_7.importCryptoPrimitives(primitives), algorithm, parameters);
        }

        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
            return this.constraints.permits(JsseUtils_7.importCryptoPrimitives(primitives), algorithm, key, parameters);
        }

        BCAlgorithmConstraints unwrap() {
            return this.constraints;
        }
    }
}
