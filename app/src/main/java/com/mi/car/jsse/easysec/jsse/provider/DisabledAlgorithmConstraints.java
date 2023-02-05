package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jsse.java.security.BCCryptoPrimitive;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHParameterSpec;

/* access modifiers changed from: package-private */
public class DisabledAlgorithmConstraints extends AbstractAlgorithmConstraints {
    private static final String INCLUDE_PREFIX = "include ";
    private static final String KEYWORD_KEYSIZE = "keySize";
    private static final Logger LOG = Logger.getLogger(DisabledAlgorithmConstraints.class.getName());
    private final Map<String, List<Constraint>> constraintsMap;
    private final Set<String> disabledAlgorithms;

    static DisabledAlgorithmConstraints create(AlgorithmDecomposer decomposer, String propertyName, String defaultValue) {
        String[] entries = PropertyUtils.getStringArraySecurityProperty(propertyName, defaultValue);
        if (entries == null) {
            return null;
        }
        Set<String> disabledAlgorithms2 = new HashSet<>();
        Map<String, List<Constraint>> constraintsMap2 = new HashMap<>();
        for (int i = 0; i < entries.length; i++) {
            if (!addConstraint(disabledAlgorithms2, constraintsMap2, entries[i])) {
                LOG.warning("Ignoring unsupported entry in '" + propertyName + "': " + entries[i]);
            }
        }
        return new DisabledAlgorithmConstraints(decomposer, Collections.unmodifiableSet(disabledAlgorithms2), Collections.unmodifiableMap(constraintsMap2));
    }

    private static boolean addConstraint(Set<String> disabledAlgorithms2, Map<String, List<Constraint>> constraintsMap2, String entry) {
        if (entry.regionMatches(true, 0, INCLUDE_PREFIX, 0, INCLUDE_PREFIX.length())) {
            return false;
        }
        int spacePos = entry.indexOf(32);
        if (spacePos < 0) {
            String algorithm = getCanonicalAlgorithm(entry);
            disabledAlgorithms2.add(algorithm);
            addConstraint(constraintsMap2, algorithm, DisabledConstraint.INSTANCE);
            return true;
        }
        String algorithm2 = getCanonicalAlgorithm(entry.substring(0, spacePos));
        String policy = entry.substring(spacePos + 1).trim();
        if (policy.indexOf(38) >= 0 || !policy.startsWith(KEYWORD_KEYSIZE)) {
            return false;
        }
        StringTokenizer tokenizer = new StringTokenizer(policy);
        if (!KEYWORD_KEYSIZE.equals(tokenizer.nextToken())) {
            return false;
        }
        BinOp op = BinOp.parse(tokenizer.nextToken());
        int constraint = Integer.parseInt(tokenizer.nextToken());
        if (tokenizer.hasMoreTokens()) {
            return false;
        }
        addConstraint(constraintsMap2, algorithm2, new KeySizeConstraint(op, constraint));
        return true;
    }

    private static void addConstraint(Map<String, List<Constraint>> constraintsMap2, String algorithm, Constraint constraint) {
        List<Constraint> constraintList = constraintsMap2.get(algorithm);
        if (constraintList == null) {
            constraintList = new ArrayList<>(1);
            constraintsMap2.put(algorithm, constraintList);
        }
        constraintList.add(constraint);
    }

    private static String getCanonicalAlgorithm(String algorithm) {
        if ("DiffieHellman".equalsIgnoreCase(algorithm)) {
            return "DH";
        }
        return algorithm.toUpperCase(Locale.ENGLISH).replace("SHA-", "SHA");
    }

    private static String getConstraintsAlgorithm(String algorithm, AlgorithmParameters parameters) {
        String parametersAlgorithm;
        if (!(parameters == null || (parametersAlgorithm = parameters.getAlgorithm()) == null)) {
            String canonicalAlgorithm = getCanonicalAlgorithm(algorithm);
            if (canonicalAlgorithm.equalsIgnoreCase(getCanonicalAlgorithm(parametersAlgorithm))) {
                return canonicalAlgorithm;
            }
        }
        return null;
    }

    private static String getConstraintsAlgorithm(Key key) {
        String keyAlgorithm;
        if (key == null || (keyAlgorithm = JsseUtils.getKeyAlgorithm(key)) == null) {
            return null;
        }
        return getCanonicalAlgorithm(keyAlgorithm);
    }

    private DisabledAlgorithmConstraints(AlgorithmDecomposer decomposer, Set<String> disabledAlgorithms2, Map<String, List<Constraint>> constraintsMap2) {
        super(decomposer);
        this.disabledAlgorithms = disabledAlgorithms2;
        this.constraintsMap = constraintsMap2;
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, AlgorithmParameters parameters) {
        checkPrimitives(primitives);
        checkAlgorithmName(algorithm);
        if (containsAnyPartIgnoreCase(this.disabledAlgorithms, algorithm)) {
            return false;
        }
        for (Constraint constraint : getConstraints(getConstraintsAlgorithm(algorithm, parameters))) {
            if (!constraint.permits(parameters)) {
                return false;
            }
        }
        return true;
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public final boolean permits(Set<BCCryptoPrimitive> primitives, Key key) {
        return checkConstraints(primitives, null, key, null);
    }

    @Override // com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints
    public final boolean permits(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
        checkAlgorithmName(algorithm);
        return checkConstraints(primitives, algorithm, key, parameters);
    }

    private boolean checkConstraints(Set<BCCryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters parameters) {
        checkPrimitives(primitives);
        checkKey(key);
        if ((JsseUtils.isNameSpecified(algorithm) && !permits(primitives, algorithm, parameters)) || !permits(primitives, JsseUtils.getKeyAlgorithm(key), null)) {
            return false;
        }
        for (Constraint constraint : getConstraints(getConstraintsAlgorithm(key))) {
            if (!constraint.permits(key)) {
                return false;
            }
        }
        return true;
    }

    private List<Constraint> getConstraints(String algorithm) {
        List<Constraint> result;
        return (algorithm == null || (result = this.constraintsMap.get(algorithm)) == null) ? Collections.emptyList() : result;
    }

    /* access modifiers changed from: private */
    public enum BinOp {
        EQ("=="),
        GE(">="),
        GT(">"),
        LE("<="),
        LT("<"),
        NE("!=");
        
        private final String s;

        static boolean eval(BinOp op, int lhs, int rhs) {
            switch (op) {
                case EQ:
                    return lhs == rhs;
                case GE:
                    return lhs >= rhs;
                case GT:
                    return lhs > rhs;
                case LE:
                    return lhs <= rhs;
                case LT:
                    return lhs < rhs;
                case NE:
                    return lhs != rhs;
                default:
                    return true;
            }
        }

        static BinOp parse(String s2) {
            BinOp[] values = values();
            for (BinOp op : values) {
                if (op.s.equals(s2)) {
                    return op;
                }
            }
            throw new IllegalArgumentException("'s' is not a valid operator: " + s2);
        }

        private BinOp(String s2) {
            this.s = s2;
        }
    }

    /* access modifiers changed from: private */
    public static abstract class Constraint {
        private Constraint() {
        }

        /* access modifiers changed from: package-private */
        public boolean permits(AlgorithmParameters parameters) {
            return true;
        }

        /* access modifiers changed from: package-private */
        public boolean permits(Key key) {
            return true;
        }
    }

    /* access modifiers changed from: private */
    public static class DisabledConstraint extends Constraint {
        static final DisabledConstraint INSTANCE = new DisabledConstraint();

        private DisabledConstraint() {
            super();
        }

        @Override // com.mi.car.jsse.easysec.jsse.provider.DisabledAlgorithmConstraints.Constraint
        public boolean permits(Key key) {
            return false;
        }
    }

    /* access modifiers changed from: private */
    public static class KeySizeConstraint extends Constraint {
        private final int constraint;
        private final BinOp op;

        private static int getKeySize(AlgorithmParameters parameters) {
            String algorithm = parameters.getAlgorithm();
            if ("EC".equals(algorithm)) {
                try {
                    ECParameterSpec spec = (ECParameterSpec) parameters.getParameterSpec(ECParameterSpec.class);
                    if (spec != null) {
                        return spec.getOrder().bitLength();
                    }
                } catch (InvalidParameterSpecException e) {
                }
            } else if ("DiffieHellman".equals(algorithm)) {
                try {
                    DHParameterSpec spec2 = (DHParameterSpec) parameters.getParameterSpec(DHParameterSpec.class);
                    if (spec2 != null) {
                        return spec2.getP().bitLength();
                    }
                } catch (InvalidParameterSpecException e2) {
                }
            }
            return -1;
        }

        private static int getKeySize(Key key) {
            byte[] raw;
            if (key instanceof RSAKey) {
                return ((RSAKey) key).getModulus().bitLength();
            }
            if (key instanceof ECKey) {
                return ((ECKey) key).getParams().getOrder().bitLength();
            }
            if (key instanceof DSAKey) {
                DSAParams dsaParams = ((DSAKey) key).getParams();
                if (dsaParams != null) {
                    return dsaParams.getP().bitLength();
                }
            } else if (key instanceof DHKey) {
                return ((DHKey) key).getParams().getP().bitLength();
            } else {
                if (key instanceof SecretKey) {
                    SecretKey secretKey = (SecretKey) key;
                    if ("RAW".equals(secretKey.getFormat()) && (raw = secretKey.getEncoded()) != null) {
                        if (raw.length > 268435455) {
                            return 0;
                        }
                        return raw.length * 8;
                    }
                }
            }
            return -1;
        }

        KeySizeConstraint(BinOp op2, int constraint2) {
            super();
            this.op = op2;
            this.constraint = constraint2;
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.jsse.provider.DisabledAlgorithmConstraints.Constraint
        public boolean permits(AlgorithmParameters parameters) {
            return checkKeySize(getKeySize(parameters));
        }

        /* access modifiers changed from: package-private */
        @Override // com.mi.car.jsse.easysec.jsse.provider.DisabledAlgorithmConstraints.Constraint
        public boolean permits(Key key) {
            return checkKeySize(getKeySize(key));
        }

        private boolean checkKeySize(int keySize) {
            return keySize < 1 ? keySize < 0 : !BinOp.eval(this.op, keySize, this.constraint);
        }
    }
}
