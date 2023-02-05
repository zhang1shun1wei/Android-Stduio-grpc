package com.mi.car.jsse.easysec.jsse.provider;

import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.jsse.BCX509ExtendedKeyManager;
import com.mi.car.jsse.easysec.jsse.BCX509Key;
import com.mi.car.jsse.easysec.jsse.java.security.BCAlgorithmConstraints;
import com.mi.car.jsse.easysec.jsse.provider.ProvX509KeyManager;
import com.mi.car.jsse.easysec.tls.TlsUtils;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLEngine;

class ProvX509KeyManagerSimple extends BCX509ExtendedKeyManager {
    private static final Logger LOG = Logger.getLogger(ProvX509KeyManagerSimple.class.getName());
    private final boolean isInFipsMode;
    private final JcaJceHelper helper;
    private final Map<String, ProvX509KeyManagerSimple.Credential> credentials;

    private static Map<String, ProvX509KeyManagerSimple.Credential> loadCredentials(KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Map<String, ProvX509KeyManagerSimple.Credential> credentials = new HashMap(4);
        if (null != ks) {
            Enumeration aliases = ks.aliases();

            while(aliases.hasMoreElements()) {
                String alias = (String)aliases.nextElement();
                if (ks.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                    PrivateKey privateKey = (PrivateKey)ks.getKey(alias, password);
                    if (null != privateKey) {
                        X509Certificate[] certificateChain = JsseUtils.getX509CertificateChain(ks.getCertificateChain(alias));
                        if (!TlsUtils.isNullOrEmpty(certificateChain)) {
                            credentials.put(alias, new ProvX509KeyManagerSimple.Credential(alias, privateKey, certificateChain));
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableMap(credentials);
    }

    ProvX509KeyManagerSimple(boolean isInFipsMode, JcaJceHelper helper, KeyStore ks, char[] password) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        this.isInFipsMode = isInFipsMode;
        this.helper = helper;
        this.credentials = loadCredentials(ks, password);
    }

    public String chooseClientAlias(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseAlias(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public BCX509Key chooseClientKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), false);
    }

    public String chooseEngineClientAlias(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseAlias(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public BCX509Key chooseEngineClientKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), false);
    }

    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
        return this.chooseAlias(ProvX509KeyManager.getKeyTypes(new String[]{keyType}), issuers, TransportData.from(engine), true);
    }

    public BCX509Key chooseEngineServerKeyBC(String[] keyTypes, Principal[] issuers, SSLEngine engine) {
        return this.chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(engine), true);
    }

    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return this.chooseAlias(ProvX509KeyManager.getKeyTypes(new String[]{keyType}), issuers, TransportData.from(socket), true);
    }

    public BCX509Key chooseServerKeyBC(String[] keyTypes, Principal[] issuers, Socket socket) {
        return this.chooseKeyBC(ProvX509KeyManager.getKeyTypes(keyTypes), issuers, TransportData.from(socket), true);
    }

    public X509Certificate[] getCertificateChain(String alias) {
        ProvX509KeyManagerSimple.Credential credential = this.getCredential(alias);
        return null == credential ? null : (X509Certificate[])credential.certificateChain.clone();
    }

    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return this.getAliases(ProvX509KeyManager.getKeyTypes(new String[]{keyType}), issuers, (TransportData)null, false);
    }

    public PrivateKey getPrivateKey(String alias) {
        ProvX509KeyManagerSimple.Credential credential = this.getCredential(alias);
        return null == credential ? null : credential.privateKey;
    }

    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return this.getAliases(ProvX509KeyManager.getKeyTypes(new String[]{keyType}), issuers, (TransportData)null, true);
    }

    public BCX509Key getKeyBC(String keyType, String alias) {
        ProvX509KeyManagerSimple.Credential credential = this.getCredential(alias);
        return this.createKeyBC(keyType, credential);
    }

    private String chooseAlias(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManagerSimple.Match bestMatch = this.getBestMatch(keyTypes, issuers, transportData, forServer);
        if (bestMatch.compareTo(ProvX509KeyManagerSimple.Match.NOTHING) < 0) {
            String keyType = (String)keyTypes.get(bestMatch.keyTypeIndex);
            String alias = getAlias(bestMatch);
            if (LOG.isLoggable(Level.FINE)) {
                LOG.fine("Found matching key of type: " + keyType + ", returning alias: " + alias);
            }

            return alias;
        } else {
            LOG.fine("No matching key found");
            return null;
        }
    }

    private BCX509Key chooseKeyBC(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManagerSimple.Match bestMatch = this.getBestMatch(keyTypes, issuers, transportData, forServer);
        if (bestMatch.compareTo(ProvX509KeyManagerSimple.Match.NOTHING) < 0) {
            String keyType = (String)keyTypes.get(bestMatch.keyTypeIndex);
            BCX509Key keyBC = this.createKeyBC(keyType, bestMatch.credential);
            if (null != keyBC) {
                if (LOG.isLoggable(Level.FINE)) {
                    LOG.fine("Found matching key of type: " + keyType + ", from alias: " + getAlias(bestMatch));
                }

                return keyBC;
            }
        }

        LOG.fine("No matching key found");
        return null;
    }

    private BCX509Key createKeyBC(String keyType, ProvX509KeyManagerSimple.Credential credential) {
        return null == credential ? null : new ProvX509Key(keyType, credential.privateKey, credential.certificateChain);
    }

    private String[] getAliases(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        if (!this.credentials.isEmpty() && !keyTypes.isEmpty()) {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = ProvX509KeyManager.getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, forServer);
            List<ProvX509KeyManagerSimple.Match> matches = null;
            Iterator var11 = this.credentials.values().iterator();

            while(var11.hasNext()) {
                ProvX509KeyManagerSimple.Credential credential = (ProvX509KeyManagerSimple.Credential)var11.next();
                ProvX509KeyManagerSimple.Match match = this.getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);
                if (match.compareTo(ProvX509KeyManagerSimple.Match.NOTHING) < 0) {
                    matches = addToMatches(matches, match);
                }
            }

            if (null != matches && !matches.isEmpty()) {
                Collections.sort(matches);
                return getAliases(matches);
            }
        }

        return null;
    }

    private ProvX509KeyManagerSimple.Match getBestMatch(List<String> keyTypes, Principal[] issuers, TransportData transportData, boolean forServer) {
        ProvX509KeyManagerSimple.Match bestMatchSoFar = ProvX509KeyManagerSimple.Match.NOTHING;
        if (!this.credentials.isEmpty() && !keyTypes.isEmpty()) {
            int keyTypeLimit = keyTypes.size();
            Set<Principal> uniqueIssuers = ProvX509KeyManager.getUniquePrincipals(issuers);
            BCAlgorithmConstraints algorithmConstraints = TransportData.getAlgorithmConstraints(transportData, true);
            Date atDate = new Date();
            String requestedHostName = ProvX509KeyManager.getRequestedHostName(transportData, forServer);
            Iterator var11 = this.credentials.values().iterator();

            while(var11.hasNext()) {
                ProvX509KeyManagerSimple.Credential credential = (ProvX509KeyManagerSimple.Credential)var11.next();
                ProvX509KeyManagerSimple.Match match = this.getPotentialMatch(credential, keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, atDate, requestedHostName);
                if (match.compareTo(bestMatchSoFar) < 0) {
                    bestMatchSoFar = match;
                    if (match.isIdeal()) {
                        return match;
                    }

                    if (match.isValid()) {
                        keyTypeLimit = Math.min(keyTypeLimit, match.keyTypeIndex + 1);
                    }
                }
            }
        }

        return bestMatchSoFar;
    }

    private ProvX509KeyManagerSimple.Match getPotentialMatch(ProvX509KeyManagerSimple.Credential credential, List<String> keyTypes, int keyTypeLimit, Set<Principal> uniqueIssuers, BCAlgorithmConstraints algorithmConstraints, boolean forServer, Date atDate, String requestedHostName) {
        X509Certificate[] chain = credential.certificateChain;
        int keyTypeIndex = ProvX509KeyManager.getPotentialKeyType(keyTypes, keyTypeLimit, uniqueIssuers, algorithmConstraints, forServer, chain);
        if (keyTypeIndex >= 0) {
            ProvX509KeyManager.MatchQuality quality = ProvX509KeyManager.getKeyTypeQuality(this.isInFipsMode, this.helper, keyTypes, algorithmConstraints, forServer, atDate, requestedHostName, chain, keyTypeIndex);
            if (ProvX509KeyManager.MatchQuality.NONE != quality) {
                return new ProvX509KeyManagerSimple.Match(quality, keyTypeIndex, credential);
            }
        }

        return ProvX509KeyManagerSimple.Match.NOTHING;
    }

    private ProvX509KeyManagerSimple.Credential getCredential(String alias) {
        return null == alias ? null : (ProvX509KeyManagerSimple.Credential)this.credentials.get(alias);
    }

    private static List<ProvX509KeyManagerSimple.Match> addToMatches(List<ProvX509KeyManagerSimple.Match> matches, ProvX509KeyManagerSimple.Match match) {
        if (null == matches) {
            matches = new ArrayList();
        }

        ((List)matches).add(match);
        return (List)matches;
    }

    private static String getAlias(ProvX509KeyManagerSimple.Match match) {
        return match.credential.alias;
    }

    private static String[] getAliases(List<ProvX509KeyManagerSimple.Match> matches) {
        int count = matches.size();
        int pos = 0;
        String[] result = new String[count];

        ProvX509KeyManagerSimple.Match match;
        for(Iterator var4 = matches.iterator(); var4.hasNext(); result[pos++] = getAlias(match)) {
            match = (ProvX509KeyManagerSimple.Match)var4.next();
        }

        return result;
    }

    private static final class Match implements Comparable<ProvX509KeyManagerSimple.Match> {
        static final ProvX509KeyManager.MatchQuality INVALID;
        static final ProvX509KeyManagerSimple.Match NOTHING;
        final ProvX509KeyManager.MatchQuality quality;
        final int keyTypeIndex;
        final ProvX509KeyManagerSimple.Credential credential;

        Match(ProvX509KeyManager.MatchQuality quality, int keyTypeIndex, ProvX509KeyManagerSimple.Credential credential) {
            this.quality = quality;
            this.keyTypeIndex = keyTypeIndex;
            this.credential = credential;
        }

        public int compareTo(ProvX509KeyManagerSimple.Match that) {
            boolean thisValid = this.isValid();
            boolean thatValid = that.isValid();
            if (thisValid != thatValid) {
                return thisValid ? -1 : 1;
            } else if (this.keyTypeIndex != that.keyTypeIndex) {
                return this.keyTypeIndex < that.keyTypeIndex ? -1 : 1;
            } else {
                return this.quality.compareTo(that.quality);
            }
        }

        boolean isIdeal() {
            return ProvX509KeyManager.MatchQuality.OK == this.quality && 0 == this.keyTypeIndex;
        }

        boolean isValid() {
            return this.quality.compareTo(INVALID) < 0;
        }

        static {
            INVALID = ProvX509KeyManager.MatchQuality.MISMATCH_SNI;
            NOTHING = new ProvX509KeyManagerSimple.Match(ProvX509KeyManager.MatchQuality.NONE, 2147483647, (ProvX509KeyManagerSimple.Credential)null);
        }
    }

    private static class Credential {
        private final String alias;
        private final PrivateKey privateKey;
        private final X509Certificate[] certificateChain;

        Credential(String alias, PrivateKey privateKey, X509Certificate[] certificateChain) {
            this.alias = alias;
            this.privateKey = privateKey;
            this.certificateChain = certificateChain;
        }
    }
}