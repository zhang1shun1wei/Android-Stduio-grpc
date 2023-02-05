package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.jcajce.PKIXCRLStore;
import com.mi.car.jsse.easysec.util.Iterable;
import com.mi.car.jsse.easysec.util.Selector;
import com.mi.car.jsse.easysec.util.Store;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.URI;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
//import javax.naming.NamingException;
//import javax.naming.directory.InitialDirContext;

class CrlCache {
    private static final int DEFAULT_TIMEOUT = 15000;
    private static Map<URI, WeakReference<PKIXCRLStore>> cache = Collections.synchronizedMap(new WeakHashMap());

    CrlCache() {
    }

    /* JADX WARNING: Code restructure failed: missing block: B:16:0x003b, code lost:
        if (r4 == false) goto L_0x003d;
     */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    static synchronized PKIXCRLStore getCrl(CertificateFactory r12, java.util.Date r13, URI r14) throws IOException, CRLException {
        /*
        // Method dump skipped, instructions count: 109
        */
        throw new UnsupportedOperationException("Method not decompiled: com.mi.car.jsse.easysec.jce.provider.CrlCache.getCrl(java.security.cert.CertificateFactory, java.util.Date, java.net.URI):com.mi.car.jsse.easysec.jcajce.PKIXCRLStore");
    }

//    private static Collection getCrlsFromLDAP(CertificateFactory certFact, URI distributionPoint) throws IOException, CRLException {
//        Map<String, String> env = new Hashtable<>();
//        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
//        env.put("java.naming.provider.url", distributionPoint.toString());
//        try {
//            byte[] val = (byte[]) new InitialDirContext((Hashtable) env).getAttributes("").get("certificateRevocationList;binary").get();
//            if (val != null && val.length != 0) {
//                return certFact.generateCRLs(new ByteArrayInputStream(val));
//            }
//            throw new CRLException("no CRL returned from: " + distributionPoint);
//        } catch (NamingException e) {
//            throw new CRLException("issue connecting to: " + distributionPoint.toString(), e);
//        }
//    }

    private static Collection getCrls(CertificateFactory certFact, URI distributionPoint) throws IOException, CRLException {
        HttpURLConnection crlCon = (HttpURLConnection) distributionPoint.toURL().openConnection();
        crlCon.setConnectTimeout(DEFAULT_TIMEOUT);
        crlCon.setReadTimeout(DEFAULT_TIMEOUT);
        InputStream crlIn = crlCon.getInputStream();
        Collection crls = certFact.generateCRLs(crlIn);
        crlIn.close();
        return crls;
    }

    private static class LocalCRLStore<T extends CRL> implements PKIXCRLStore, Iterable<CRL> {
        private Collection<CRL> _local;

        public LocalCRLStore(Store<CRL> collection) {
            this._local = new ArrayList(collection.getMatches(null));
        }

        @Override // com.mi.car.jsse.easysec.jcajce.PKIXCRLStore, com.mi.car.jsse.easysec.util.Store
        public Collection getMatches(Selector selector) {
            if (selector == null) {
                return new ArrayList(this._local);
            }
            List<CRL> col = new ArrayList<>();
            for (CRL obj : this._local) {
                if (selector.match(obj)) {
                    col.add(obj);
                }
            }
            return col;
        }

        @Override // com.mi.car.jsse.easysec.util.Iterable, java.lang.Iterable
        public Iterator<CRL> iterator() {
            return getMatches(null).iterator();
        }
    }
}
