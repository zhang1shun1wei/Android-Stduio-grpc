package com.mi.car.jsse.easysec.jce.provider;

import com.mi.car.jsse.easysec.asn1.ASN1EncodableVector;
import com.mi.car.jsse.easysec.asn1.ASN1GeneralizedTime;
import com.mi.car.jsse.easysec.asn1.ASN1ObjectIdentifier;
import com.mi.car.jsse.easysec.asn1.ASN1OctetString;
import com.mi.car.jsse.easysec.asn1.ASN1Primitive;
import com.mi.car.jsse.easysec.asn1.ASN1Sequence;
import com.mi.car.jsse.easysec.asn1.DERSequence;
import com.mi.car.jsse.easysec.asn1.ocsp.BasicOCSPResponse;
import com.mi.car.jsse.easysec.asn1.ocsp.CertID;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPObjectIdentifiers;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPRequest;
import com.mi.car.jsse.easysec.asn1.ocsp.OCSPResponse;
import com.mi.car.jsse.easysec.asn1.ocsp.Request;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponseBytes;
import com.mi.car.jsse.easysec.asn1.ocsp.ResponseData;
import com.mi.car.jsse.easysec.asn1.ocsp.SingleResponse;
import com.mi.car.jsse.easysec.asn1.ocsp.TBSRequest;
import com.mi.car.jsse.easysec.asn1.x509.Extensions;
import com.mi.car.jsse.easysec.asn1.x509.GeneralName;
import com.mi.car.jsse.easysec.jcajce.PKIXCertRevocationCheckerParameters;
import com.mi.car.jsse.easysec.jcajce.util.JcaJceHelper;
import com.mi.car.jsse.easysec.util.io.Streams;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.ref.WeakReference;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;

/* access modifiers changed from: package-private */
class OcspCache {
    private static final int DEFAULT_TIMEOUT = 15000;
    private static final int DEFAULT_MAX_RESPONSE_SIZE = 32768;
    private static Map<URI, WeakReference<Map<CertID, OCSPResponse>>> cache = Collections.synchronizedMap(new WeakHashMap());

    OcspCache() {
    }

    static OCSPResponse getOcspResponse(CertID certID, PKIXCertRevocationCheckerParameters parameters, URI ocspResponder, X509Certificate responderCert, List<Extension> ocspExtensions, JcaJceHelper helper) throws CertPathValidatorException {
        Map<CertID, OCSPResponse> responseMap = null;
        WeakReference<Map<CertID, OCSPResponse>> markerRef = (WeakReference)cache.get(ocspResponder);
        if (markerRef != null) {
            responseMap = (Map)markerRef.get();
        }

        ASN1GeneralizedTime nextUp;
        if (responseMap != null) {
            OCSPResponse response = (OCSPResponse)responseMap.get(certID);
            if (response != null) {
                BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(ASN1OctetString.getInstance(response.getResponseBytes().getResponse()).getOctets());
                ResponseData responseData = ResponseData.getInstance(basicResp.getTbsResponseData());
                ASN1Sequence s = responseData.getResponses();

                for(int i = 0; i != s.size(); ++i) {
                    SingleResponse resp = SingleResponse.getInstance(s.getObjectAt(i));
                    if (certID.equals(resp.getCertID())) {
                        nextUp = resp.getNextUpdate();

                        try {
                            if (nextUp != null && parameters.getValidDate().after(nextUp.getDate())) {
                                responseMap.remove(certID);
                                response = null;
                            }
                        } catch (ParseException var26) {
                            responseMap.remove(certID);
                            response = null;
                        }
                    }
                }

                if (response != null) {
                    return response;
                }
            }
        }

        URL ocspUrl;
        try {
            ocspUrl = ocspResponder.toURL();
        } catch (MalformedURLException var25) {
            throw new CertPathValidatorException("configuration error: " + var25.getMessage(), var25, parameters.getCertPath(), parameters.getIndex());
        }

        ASN1EncodableVector requests = new ASN1EncodableVector();
        requests.add(new Request(certID, (Extensions)null));
        List exts = ocspExtensions;
        ASN1EncodableVector requestExtensions = new ASN1EncodableVector();
        byte[] nonce = null;

        byte[] request;
        for(int i = 0; i != exts.size(); ++i) {
            Extension ext = (Extension)exts.get(i);
            request = ext.getValue();
            if (OCSPObjectIdentifiers.id_pkix_ocsp_nonce.getId().equals(ext.getId())) {
                nonce = request;
            }

            requestExtensions.add(new com.mi.car.jsse.easysec.asn1.x509.Extension(new ASN1ObjectIdentifier(ext.getId()), ext.isCritical(), request));
        }

        TBSRequest tbsReq = new TBSRequest((GeneralName)null, new DERSequence(requests), Extensions.getInstance(new DERSequence(requestExtensions)));
        nextUp = null;

        try {
            request = (new OCSPRequest(tbsReq, null)).getEncoded();
            HttpURLConnection ocspCon = (HttpURLConnection)ocspUrl.openConnection();
            ocspCon.setConnectTimeout(15000);
            ocspCon.setReadTimeout(15000);
            ocspCon.setDoOutput(true);
            ocspCon.setDoInput(true);
            ocspCon.setRequestMethod("POST");
            ocspCon.setRequestProperty("Content-type", "application/ocsp-request");
            ocspCon.setRequestProperty("Content-length", String.valueOf(request.length));
            OutputStream reqOut = ocspCon.getOutputStream();
            reqOut.write(request);
            reqOut.flush();
            InputStream reqIn = ocspCon.getInputStream();
            int contentLength = ocspCon.getContentLength();
            if (contentLength < 0) {
                contentLength = 32768;
            }

            OCSPResponse response = OCSPResponse.getInstance(Streams.readAllLimited(reqIn, contentLength));
            if (0 == response.getResponseStatus().getIntValue()) {
                boolean validated = false;
                ResponseBytes respBytes = ResponseBytes.getInstance(response.getResponseBytes());
                if (respBytes.getResponseType().equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic)) {
                    BasicOCSPResponse basicResp = BasicOCSPResponse.getInstance(respBytes.getResponse().getOctets());
                    validated = ProvOcspRevocationChecker.validatedOcspResponse(basicResp, parameters, nonce, responderCert, helper);
                }

                if (!validated) {
                    throw new CertPathValidatorException("OCSP response failed to validate", (Throwable)null, parameters.getCertPath(), parameters.getIndex());
                } else {
                    markerRef = (WeakReference)cache.get(ocspResponder);
                    if (markerRef != null) {
                        responseMap = (Map)markerRef.get();
                        responseMap.put(certID, response);
                    } else {
                        Map<CertID, OCSPResponse> responseMap1 = new HashMap();
                        responseMap1.put(certID, response);
                        cache.put(ocspResponder, new WeakReference(responseMap1));
                    }

                    return response;
                }
            } else {
                throw new CertPathValidatorException("OCSP responder failed: " + response.getResponseStatus().getValue(), (Throwable)null, parameters.getCertPath(), parameters.getIndex());
            }
        } catch (IOException var24) {
            throw new CertPathValidatorException("configuration error: " + var24.getMessage(), var24, parameters.getCertPath(), parameters.getIndex());
        }
    }
}
