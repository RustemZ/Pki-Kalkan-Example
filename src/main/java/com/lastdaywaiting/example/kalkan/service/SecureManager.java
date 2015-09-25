/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.lastdaywaiting.example.kalkan.service;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.CMSException;
import kz.gov.pki.kalkan.jce.provider.cms.CMSProcessableByteArray;
import kz.gov.pki.kalkan.jce.provider.cms.CMSSignedData;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformation;
import kz.gov.pki.kalkan.jce.provider.cms.SignerInformationStore;
import kz.gov.pki.kalkan.util.encoders.Base64;
import org.apache.commons.lang.time.DateUtils;

/**
 * Вся логика по проверки подписи находиться в этом классе
 * основные методы класса isGoodSignature и verifyCMSSignature, от них и надо вести анализ кода 
 * @author Rustem.Zhunusov_at_gmail.com
 */
public class SecureManager {
    final static Logger log = Logger.getLogger(SecureManager.class.getName());
    final static Map<String, TypeOfCrlLoaded> MAP_OF_LOAD_CRL_LABEL; // 
    final static Map MAP_OF_XCRL;
    final static Map<String, Date> MAP_OF_LOAD_CRL_TIME;
    final static Map<String, String> MAP_OF_CRL_PATH;
    final static Integer HOURS_OF_RELOAD = 3;

    // Всего в данном примере используется четыре  возможных варианта 
    // загрузки CRL-файлов это два типа сертификатов (RSA и GOST) для двух типов систем (НУЦ_1 и НУЦ_2)
    final static String CRL_GOST_1 = "CRL_GOST_1";
    final static String CRL_GOST_2 = "CRL_GOST_2";
    final static String CRL_RSA_1 = "CRL_RSA_1";
    final static String CRL_RSA_2 = "CRL_RSA_2";
    final static String NO_OBJECT = "NO_OBJECT";

    final static String DEFAUL_CERT_NUC1_GOST="/kz/pki/ca/nuc1/new_NCA_GOST.cer";
    final static String DEFAUL_CERT_NUC1_RSA="/kz/pki/ca/nuc1/new_NCA_RSA.cer";
    final static String DEFAUL_CERT_NUC2_GOST="/kz/pki/ca/nuc2/knca_root.crt";
    final static String DEFAUL_CERT_NUC2_RSA="/kz/pki/ca/nuc2/knca_rsa.crt";
    final static String DEFAUL_CERT_KUC_GOST="/kz/pki/ca/kuc/rca_gost.crt";
    final static String DEFAUL_CERT_KUC_RSA="/kz/pki/ca/kuc/rca_rsa.crt";
    //static final String NO_ERROR = "NO_ERROR";
    final static Boolean DEFAUL_USE_PROXY=true;
    final static String DEFAUL_PROXY_ADDRESS="fake.proxy.kz";
    final static Integer DEFAUL_PROXY_PORT=3128;
    static AtomicBoolean canWorkWithKalkan = new AtomicBoolean(false);
    static String kalkanErrorMessage = "";
    static String providerName = "No_Name";
    

    static { // #1
        try {
            Provider kalkanProvider = new KalkanProvider();
            //Добавление провайдера в java.security.Security
            boolean exists = false;
            Provider[] providers = Security.getProviders();
            for (Provider p : providers) {
                if (p.getName().equals(kalkanProvider.getName())) {
                    exists = true;
                }
            }
            if (!exists) {
                Security.addProvider(kalkanProvider);
            } else {
                // да нужно заменять провайдер каждый раз когда загружаеться класс, иначе провайдер будет не доступен; 
                Security.removeProvider(kalkanProvider.getName());
                Security.addProvider(kalkanProvider);
            }
            canWorkWithKalkan.set(true);
            providerName = kalkanProvider.getName();
            // Почему Error, а не Exception - 
            // чтобы поймать например ошибки когда провайдер скомпилированный под яву 1.7 запускаетьс на  яве 1.6
        } catch (Error ex) {
            log.severe("Не могу загрузить Kalkan провайдер " + ex.getMessage());
            kalkanErrorMessage = ex.getMessage();
            canWorkWithKalkan.set(false);
        }

    }
    
    static { //#2
        MAP_OF_LOAD_CRL_LABEL = new ConcurrentHashMap(); // описание состояния загрузки CRL-файлов 
        MAP_OF_XCRL = new ConcurrentHashMap();  // последний версий загруженных CRL-файлов лежат здесь
        MAP_OF_LOAD_CRL_TIME = new ConcurrentHashMap();  // когда CRL-файлов загрузили в последний раз
        MAP_OF_CRL_PATH = new ConcurrentHashMap(); // путь для загрузки CRL-файлов , здесь в примере он захаркоден

        MAP_OF_CRL_PATH.put(CRL_RSA_1, "http://crl.pki.kz/crl/Rsa0.crl");
        MAP_OF_CRL_PATH.put(CRL_RSA_2, "http://crl.pki.kz/crl/Rsa2.crl");
        MAP_OF_CRL_PATH.put(CRL_GOST_1, "http://crl.pki.kz/crl/Gost0.crl");
        MAP_OF_CRL_PATH.put(CRL_GOST_2, "http://crl.pki.kz/crl/Gost2.crl");
        String[] clrsArray = {CRL_GOST_1, CRL_GOST_2, CRL_RSA_1, CRL_RSA_2};
        for (String crl : clrsArray) {
            MAP_OF_LOAD_CRL_LABEL.put(crl, TypeOfCrlLoaded.NO_LOAD); //инициализация - загрузки CRL-файлов еще небыло
            MAP_OF_XCRL.put(crl, NO_OBJECT); //инициализация - соотвественно и самих CRL-файлов еще нет

        }
    }


    
    String respName;  
    String realBinIin ;
    TypeOfRespondent typeOfRespondent;
    String verifyErrorMsg = "";


    String pathCertNuc1Gost = DEFAUL_CERT_NUC1_GOST;
    String pathCertNuc1Rca = DEFAUL_CERT_NUC1_RSA;
    String pathCertNuc2Gost = DEFAUL_CERT_NUC2_GOST;
    String pathCertNuc2Rca = DEFAUL_CERT_NUC2_RSA;
    String pathCertKucGost = DEFAUL_CERT_KUC_GOST;
    String pathCertKucRca = DEFAUL_CERT_KUC_RSA;

    Boolean useProxy = DEFAUL_USE_PROXY;
    String proxyAddress = DEFAUL_PROXY_ADDRESS;
    Integer proxyPort = DEFAUL_PROXY_PORT;
//    String errorJsonForSignatureCheck = "";

    public SecureManager(String realBinIin, String respName, Integer respCode) {
        this.realBinIin = realBinIin;
        this.respName = respName;
        this.typeOfRespondent = TypeOfRespondent.findByCode( respCode );
    }

    public String getLastErrorMsg() {
        return verifyErrorMsg;
    }


    public boolean isGoodSignature(String signedData, String signature) {
        if (!canWorkWithKalkan.get()) {
            verifyErrorMsg = "Провайдер 'KalKan' не был загружен. Причина:" + kalkanErrorMessage;
            return false;
        }
        Boolean result = verifyCMSSignature(signature, signedData);
        return result;
    }

    private CMSSignedData createCMSSignedData(String sigantureToVerify, String signedData) throws CMSException, IOException {
        CMSSignedData cms = new CMSSignedData(Base64.decode(sigantureToVerify));
        boolean isAttachedContent = cms.getSignedContent() != null;
        if (isAttachedContent) {
            cms = new CMSSignedData(cms.getEncoded());
        } else {
            CMSProcessableByteArray data = new CMSProcessableByteArray(signedData.getBytes("UTF-8"));
            cms = new CMSSignedData(data, cms.getEncoded());
        }
        return cms;
    }

    /**
     * Основной метод который и проверяет валидность подписи данных
     *
     * @param sigantureToVerify - подпись
     * @param signedData - данные
     * @return
     */
    public Boolean verifyCMSSignature(String sigantureToVerify, String signedData) {
        verifyErrorMsg = "Ошибка не определена";
        try {
            CMSSignedData cms = createCMSSignedData(sigantureToVerify, signedData);

            SignerInformationStore signers = cms.getSignerInfos();
            CertStore clientCerts = cms.getCertificatesAndCRLs("Collection", providerName);
            if (!reCheckClientSignature(signers, clientCerts)) {
                return false;
            }
            if (isBadBinOrIin(signers, clientCerts)) {
                return false;
            }

            if (isBadKeyUsage(signers, clientCerts)) {
                return false;
            }
            try {
                if (checkNucOneCertificateType(signers, clientCerts)) {
                    return true;
                } else if (checkNucTwoCertificateType(signers, clientCerts)) {
                    return true;
                } else {
                    verifyErrorMsg = "Сертификат(ы) подписавший отчет не был выдан НУЦ РК.";
                    return false;
                }
            } catch (Exception ex) {
                verifyErrorMsg = ex.getMessage();
                return false;
            }

        } catch (Exception e) {
            if ((e.getCause() instanceof SignatureException)) {
                verifyErrorMsg = "SIGNATURE_VALIDATION_ERROR : " + e.getMessage();
            } else {
                verifyErrorMsg = "COMMON_ERROR : " + e.getMessage();
            }
            log.severe(verifyErrorMsg);
            return false;
        }
    }


    private Certificate createCerificate_nuc2_gost() {
        return createCerificateByFile(pathCertNuc2Gost, "'НУЦ 2.0 ГОСТ'");
    }

    private Certificate createCerificate_nuc2_rsa() {
        return createCerificateByFile(pathCertNuc2Rca, "'НУЦ 2.0 RSA'");
    }

    private Certificate createCerificate_kuc_gost() {
        return createCerificateByFile(pathCertKucGost, "'КУЦ ГОСТ'");
    }

    private Certificate createCerificate_kuc_rsa() {
        return createCerificateByFile(pathCertKucRca, "'КУЦ RSA'");
    }

    private Certificate createCerificate_nuc1_gost() {
        return createCerificateByFile(pathCertNuc1Gost, "'НУЦ 1.0 ГОСТ'");
    }

    private Certificate createCerificate_nuc1_rsa() {
        return createCerificateByFile(pathCertNuc1Rca, "'НУЦ 1.0 RSA'");
    }

    private Certificate createCerificateByFile(String fileName, String storeDescript) {
        CertPath cp = null;
        try {
            InputStream inputStream = this.getClass().getResourceAsStream(fileName);
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", providerName);
            cp = certFactory.generateCertPath(inputStream, "PKCS7");
            inputStream.close();
            //IOUtils.closeQuietly(fis);
        } catch (Exception ex) {
            throw new RuntimeException("ORE SIGN: Не смог создать сертификат из хранилища '"
                    + fileName + "' для " + storeDescript + ".", ex);
        }

        List<? extends Certificate> certs = cp.getCertificates();
        if (certs.size() == 1) {
            System.out.println("Создали сертификат " + fileName + " для " + storeDescript);
            return certs.get(0);
        } else {
            throw new RuntimeException("В хранилище '"
                    + fileName + "' для " + storeDescript
                    + " должно быть только 1 сертификат а надено " + certs.size());
        }

    }


    public String getRespName() {
        return respName;
    }

    public void setRespName(String respName) {
        this.respName = respName;
    }

    public String getRealBinIin() {
        return realBinIin;
    }

    public void setRealBinIin(String realBinIin) {
        this.realBinIin = realBinIin;
    }

    public TypeOfRespondent getTypeOfRespondent() {
        return typeOfRespondent;
    }

    public void setTypeOfRespondent(TypeOfRespondent typeOfRespondent) {
        this.typeOfRespondent = typeOfRespondent;
    }

    public boolean differentBins(String bin_iin) {
        if (bin_iin.length() > 12) {
            bin_iin = bin_iin.substring(0, 12);
        }
        boolean result = !getRealBinIin().equals(bin_iin);
        return result;
    }

//    public String getErrorJsonForSignatureCheck() {
//        return errorJsonForSignatureCheck;
//    }
//
//    public void setErrorJsonForSignatureCheck(String errorJsonForSignatureCheck) {
//        this.errorJsonForSignatureCheck = errorJsonForSignatureCheck;
//    }

    /**
     * Проверим то что сертификаты в подписи действительно подписали сообщение
     *
     * @param signers
     * @param clientCerts
     * @return
     */
    private boolean reCheckClientSignature(SignerInformationStore signers, CertStore clientCerts) throws
            CertStoreException, NoSuchAlgorithmException, NoSuchProviderException, CMSException {
        Iterator it = signers.getSigners().iterator();

        boolean overAllResult = true;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            int indexOfSigner = 0;
            while (certIt.hasNext()) {
                indexOfSigner++;
                X509Certificate cert = (X509Certificate) certIt.next();
                //System.out.println( "------ Сертификат внутри подписи: " + indexOfSigner+ " ----- ");
                //System.out.println( cert );
                try {
                    cert.checkValidity();
                    overAllResult = (overAllResult) && (signer.verify(cert, providerName));
                } catch (CertificateExpiredException ex) {
                    verifyErrorMsg = "Срок действия Сертификата которым подписали отчет прошел!";
                    Logger.getLogger(SecureManager.class.getName()).log(Level.SEVERE, "ORE SIGN2:", ex);
                    return false;
                } catch (CertificateNotYetValidException ex) {
                    verifyErrorMsg = "Сертификат которым подписали отчет уже не действителен!";
                    Logger.getLogger(SecureManager.class.getName()).log(Level.SEVERE, "ORE SIGN3:", ex);
                    return false;
                }
            }
            if (indexOfSigner == 0) {
                verifyErrorMsg = "Есть подпись данных, но не найден сертификат чтобы перепроверить эту подпись!";
            }

            if (!overAllResult) {
                verifyErrorMsg = "Перепроверка подписи данных и сертификата дала ошибку!";
            }
        }
        return overAllResult;
    }

    /**
     * Проверка совподают ли БИН в подписи с тем БИНом котрый респодент зарегистрировался 
     * в приложений. Здесь проверка всегда проходит успешно так как я в данном примере передаю правильный БИН в post-запросе
     * В реальной системе Вы можете например использовать другой сертификат для SSL-аутентификаций респондента
     * в этом случае БИНы могут не совподать. 
     * Для эксперемента вы можете поменят БИН в этом пример когда посылаете post-запрос с браузера. 
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException 
     */
    private boolean isBadBinOrIin(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        if (signers.getSigners().size() == 0) {
            verifyErrorMsg = "В Отчете не найдены подписи.";
            return true;
        }
        Iterator it = signers.getSigners().iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            //System.out.println(  );
            if (certCollection.size() == 0) {
                verifyErrorMsg = "В Отчете не найдены сертификаты которыми подписан Отчет.";
                return true;
            }
            while (certIt.hasNext()) {
                X509Certificate cert = (X509Certificate) certIt.next();
                String subj = cert.getSubjectDN().getName();
                Pattern pt;
                Matcher m;
                if (typeOfRespondent.equals(TypeOfRespondent.FIRM)) {
                    pt = Pattern.compile("BIN(\\d{12})");
                    m = pt.matcher(subj); // get a matcher object
                    if (m.find()) {
                        if (realBinIin.equals(m.group(1))) {
                            return false;
                        } else {
                            verifyErrorMsg = "Для подписания Отчета небходимо использовать сертификат с БИН '" + realBinIin
                                    + "' , а не c БИНом '" + m.group(1) + "'. ";
                        }
                    } else {
                        verifyErrorMsg = "В сертификате подпиcавшем отчет не найден БИН '" + realBinIin
                                + "' .";
                    }
                } else {
                    pt = Pattern.compile("IIN(\\d{12})");
                    m = pt.matcher(subj); // get a matcher object
                    if (m.find()) {
                        if (realBinIin.equals(m.group(1))) {
                            return false;
                        } else {
                            verifyErrorMsg = "Для подписания Отчета небходимо использовать сертификат с ИИН '" + realBinIin
                                    + "' , а не c ИИНом '" + m.group(1) + "'. ";
                        }
                    } else {
                        verifyErrorMsg = "В сертификате подпиcавшем отчет не найден ИИН '" + realBinIin
                                + "' .";
                    }
                }
            }
        }
        return true;
    }

    /**
     * Нужно чтобы у сертификата стояло свойство 'неотрекаемость'. 
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException 
     */
    private boolean isBadKeyUsage(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        if (signers.getSigners().size() == 0) {
            verifyErrorMsg = "В Отчете не найдены подписи.";
            return true;
        }
        Iterator it = signers.getSigners().iterator();
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            if (certCollection.size() == 0) {
                verifyErrorMsg = "В Отчете не найдены сертификаты которыми подписан Отчет.";
                return true;
            }
            while (certIt.hasNext()) {
                X509Certificate cert = (X509Certificate) certIt.next();
                if (cert.getKeyUsage()[0] && cert.getKeyUsage()[1]) {
                    continue;
                } else {
                    verifyErrorMsg = "Для продписания Отчета необходимо использовать сертификат c ключем 'Неотрекаемость'.";
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Проверка подписи на то что она подписана сертификатом от системы НУЦ_1 и
     * если да то проверка отозванности сертификата
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean checkNucOneCertificateType(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {

        Iterator it = signers.getSigners().iterator();
        boolean result = false;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            if (certCollection.size() == 0) {
                throw new RuntimeException("В Отчете не найдены сертификаты которыми подписан Отчет.");
            }
            while (certIt.hasNext()) {
                X509Certificate userCert = (X509Certificate) certIt.next();
                X509Certificate certForCheck = null;
                boolean isMyVersion = false;
                try {
                    if (TypeOfRespondent.FIRM.equals(typeOfRespondent)) {
                        X509Certificate certNuc1Gost = (X509Certificate) createCerificate_nuc1_gost();
                        userCert.verify(certNuc1Gost.getPublicKey(), providerName);
                        certForCheck = certNuc1Gost;
                    } else {
                        X509Certificate certNuc1Rsa = (X509Certificate) createCerificate_nuc1_rsa();
                        userCert.verify(certNuc1Rsa.getPublicKey(), providerName);
                        certForCheck = certNuc1Rsa;
                    }

                    isMyVersion = true;
                } catch (Exception ex) {
                    // не подписан сертификатом старого типа НУЦ 1
                    result = false;
                }
                if (isMyVersion) { // если данные были подписанный сертфикатом от системы НУЦ_1 то 
                    try {
                        certForCheck.checkValidity(); // проверяем валидность сертификата
                    } catch (CertificateExpiredException ex) {
                        throw new RuntimeException("Отчет подписан сертификатом НУЦ 1.0, но корневым сертификатом НУЦ 1.0 уже нельзя пользоваться");
                    } catch (CertificateNotYetValidException ex) {
                        throw new RuntimeException("Отчет подписан сертификатом НУЦ 1.0, но корневой сертификат НУЦ 1.0 уже не действителен.");
                    }
                    try {
                        if (isNotRevokedCertNucOne(userCert)) {  // проверяем отозваность сертификата
                            return true;
                        } else {
                            throw new RuntimeException("Cертификат подписавший отчет был отозван.");
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException(ex.getMessage());
                    }
                }
            }
        }
        return result;
    }

    /**
     * Проверка подписи на то что она подписана сертификатом от системы НУЦ_2 и
     * если да то проверка отозванности сертификата
     *
     * @param signers
     * @param clientCerts
     * @return
     * @throws CertStoreException
     */
    private boolean checkNucTwoCertificateType(SignerInformationStore signers, CertStore clientCerts) throws CertStoreException {
        Iterator it = signers.getSigners().iterator();
        boolean result = false;
        while (it.hasNext()) {
            SignerInformation signer = (SignerInformation) it.next();
            X509CertSelector signerConstraints = signer.getSID();
            Collection certCollection = clientCerts.getCertificates(signerConstraints);
            Iterator certIt = certCollection.iterator();
            //System.out.println(  );
            if (certCollection.size() == 0) {
                throw new RuntimeException("В Отчете не найдены сертификаты которыми подписан Отчет.");
            }
            while (certIt.hasNext()) {
                X509Certificate userCert = (X509Certificate) certIt.next();
                boolean isMyVersion = false;
                X509Certificate certForCheck = null;
                try {
                    if (TypeOfRespondent.FIRM.equals(typeOfRespondent)) {
                        X509Certificate certNuc2Gost = (X509Certificate) createCerificate_nuc2_gost();
                        X509Certificate certKucGost = (X509Certificate) createCerificate_kuc_gost();
                        userCert.verify(certNuc2Gost.getPublicKey(), providerName);
                        certNuc2Gost.verify(certKucGost.getPublicKey(), providerName);
                        certForCheck = certNuc2Gost;
                    } else {
                        X509Certificate certNuc2Rsa = (X509Certificate) createCerificate_nuc2_rsa();
                        X509Certificate certKucRsa = (X509Certificate) createCerificate_kuc_rsa();
                        userCert.verify(certNuc2Rsa.getPublicKey(), providerName);
                        certNuc2Rsa.verify(certKucRsa.getPublicKey(), providerName);
                        certForCheck = certNuc2Rsa;
                    }

                    isMyVersion = true;
                } catch (Exception ex) {
                    result = false;

                }
                if (isMyVersion) { // если данные были подписанный сертфикатом от системы НУЦ_1 то 
                    try {
                        certForCheck.checkValidity();
                    } catch (CertificateExpiredException ex) {
                        throw new RuntimeException("Отчет подписан сертификатом НУЦ 2.0, но корневым сертификатом НУЦ 2.0 уже нельзя пользоваться");
                    } catch (CertificateNotYetValidException ex) {
                        throw new RuntimeException("Отчет подписан сертификатом НУЦ 2.0, но корневой сертификат НУЦ 2.0 уже не действителен.");
                    }

                    try {
                        if (isNotRevokedCertNucTwo(userCert)) {
                            result = true;
                            return true;
                        } else {
                            throw new RuntimeException("Cертификат подписавший отчет был отозван.");
                        }
                    } catch (Exception ex) {
                        throw new RuntimeException(ex.getMessage());
                    }
                }

            }
        }
        return result;
    }

    public String getPathCertNuc1Gost() {
        return pathCertNuc1Gost;
    }

    public void setPathCertNuc1Gost(String pathCertNuc1Gost) {
        this.pathCertNuc1Gost = pathCertNuc1Gost;
    }

    public String getPathCertNuc1Rca() {
        return pathCertNuc1Rca;
    }

    public void setPathCertNuc1Rca(String pathCertNuc1Rca) {
        this.pathCertNuc1Rca = pathCertNuc1Rca;
    }

    public String getPathCertNuc2Gost() {
        return pathCertNuc2Gost;
    }

    public void setPathCertNuc2Gost(String pathCertNuc2Gost) {
        this.pathCertNuc2Gost = pathCertNuc2Gost;
    }

    public String getPathCertNuc2Rca() {
        return pathCertNuc2Rca;
    }

    public void setPathCertNuc2Rca(String pathCertNuc2Rca) {
        this.pathCertNuc2Rca = pathCertNuc2Rca;
    }

    public String getPathCertKucGost() {
        return pathCertKucGost;
    }

    public void setPathCertKucGost(String pathCertKucGost) {
        this.pathCertKucGost = pathCertKucGost;
    }

    public String getPathCertKucRca() {
        return pathCertKucRca;
    }

    public void setPathCertKucRca(String pathCertKucRca) {
        this.pathCertKucRca = pathCertKucRca;
    }


    /**
     * отозвание сертификаты для физиков находятся в CRL-файле для RSA отозвание
     * сертификаты для юриков находятся в CRL-файле для GOST
     *
     * @param currentRespType - тип респондента физическое лицо или юридическое
     * @param versionPkiSdk - Какой сертификат используеться НУЦ_1 или НУЦ_2
     * @return
     */
    private String findCurrentCrlName(TypeOfRespondent currentRespType, int versionPkiSdk) {
        if (versionPkiSdk == 1) {
            if (TypeOfRespondent.FIRM.equals(currentRespType)) {
                return CRL_GOST_1;
            } else {
                return CRL_RSA_1;
            }
        } else if (versionPkiSdk == 2) {
            if (TypeOfRespondent.FIRM.equals(currentRespType)) {
                return CRL_GOST_2;
            } else {
                return CRL_RSA_2;
            }
        } else {
            throw new RuntimeException("Не найдена Проверка отозвоности для "
                    + currentRespType.toString() + " и версий  PKI SDK =" + versionPkiSdk);
        }
    }

    /**
     * Нужно ли подгружать из инета CRL-файл или нет ?
     *
     * @param crlName
     * @return
     */
    private boolean isNeedLoadCrlObject(String crlName) {
        if (TypeOfCrlLoaded.NO_LOAD.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            return true; // да, если его еще не загружали
        } else if (TypeOfCrlLoaded.LOADING.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            return false; // нет, если загрузку начали но она не завершилась 
        } else if (TypeOfCrlLoaded.LOADED.equals(MAP_OF_LOAD_CRL_LABEL.get(crlName))) {
            Date currentDt = new Date();
            Date lastLoadedCrl = MAP_OF_LOAD_CRL_TIME.get(crlName);
            Date checkDt = DateUtils.addHours(lastLoadedCrl, HOURS_OF_RELOAD);
            if (checkDt.before(currentDt)) {
                return true;  // да, если последняя загрузка произошла HOURS_OF_RELOAD часов тому назад    
            } else {
                return false;
            }
        } else {
            throw new RuntimeException("Условия для состоние не определены " + MAP_OF_LOAD_CRL_LABEL.get(crlName));
        }
    }


    /**
     * Загрузка CRL-файла с инета, так как у меня прокси , то пришлось писать
     * код и для него
     *
     * @param crlName
     */
    private void loadCrlObject(String crlName) {
        TypeOfCrlLoaded oldState = MAP_OF_LOAD_CRL_LABEL.get(crlName);
        if (TypeOfCrlLoaded.LOADING.equals(oldState)) {
            return;
        }
        MAP_OF_LOAD_CRL_LABEL.put(crlName, TypeOfCrlLoaded.LOADING);
        String location = MAP_OF_CRL_PATH.get(crlName);
        try {
            URL url = new URL(location);
            HttpURLConnection conn = null;
            if (useProxy) {
                Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyAddress, proxyPort));
                conn = (HttpURLConnection) url.openConnection(proxy);
            } else {
                conn = (HttpURLConnection) url.openConnection();
            }
            conn.setUseCaches(false);
            conn.setDoInput(true);
            conn.connect();
            if (conn.getResponseCode() == 200) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509", "KALKAN");
                X509CRL crlObject = (X509CRL) cf.generateCRL(conn.getInputStream());
                MAP_OF_XCRL.put(crlName, crlObject);
            } else {
                String msg = "Ошибка(1) получения CRL-файла : '" + location
                        + "' : " + conn.getResponseCode() + " ,  " + conn.getResponseMessage();
                log.warning(msg);
            }
        } catch (Exception e) {
            String msg = "Ошибка(1) получения CRL-файла : '" + location
                    + "' : " + e.getMessage();
            log.warning(msg);
        }
        //MAP_OF_LOAD_CRL_LABEL.put(crlName, oldState ) ;
        MAP_OF_LOAD_CRL_TIME.put(crlName, new Date());
        MAP_OF_LOAD_CRL_LABEL.put(crlName, TypeOfCrlLoaded.LOADED);
    }

    /**
     * Найти CRL-файл для проверки на отозваность
     *
     * @param versionPkiSdk
     * @return null - возможен
     */
    private X509CRL findCrlObject( //X509Certificate certForCheck, X509Certificate userCert,
            int versionPkiSdk) {
        String crlName = findCurrentCrlName(typeOfRespondent, versionPkiSdk);
        if (isNeedLoadCrlObject(crlName)) {
            loadCrlObject(crlName);
        }
        Object result = MAP_OF_XCRL.get(crlName);
        if (result.equals(NO_OBJECT)) {
            String msg = "Не найдена проверка отозванности для " + crlName;
            log.warning(msg);
            return null;
        }
        return (X509CRL) result;
    }

    /**
     * Проверка на отозваность сертификата в системе НУЦ_1 
     * @param userCert
     * @return 
     */
    private boolean isNotRevokedCertNucOne(X509Certificate userCert) {
        X509CRL crlObject = findCrlObject(1);
        if (crlObject != null) {
            return !(crlObject.isRevoked(userCert));
        } else {
            return true;
        }
    }

    /**
     * Проверка на отозваность сертификата в системе НУЦ_2 
     * @param userCert
     * @return 
     */
    private boolean isNotRevokedCertNucTwo(X509Certificate userCert) {
        X509CRL crlObject = findCrlObject(2);
        if (crlObject != null) {
            return !(crlObject.isRevoked(userCert));
        } else {
            return true;
        }
    }

    public Boolean getUseProxy() {
        return useProxy;
    }

    public void setUseProxy(Boolean useProxy) {
        this.useProxy = useProxy;
    }

    public String getProxyAddress() {
        return proxyAddress;
    }

    public void setProxyAddress(String proxyAddress) {
        this.proxyAddress = proxyAddress;
    }

    public Integer getProxyPort() {
        return proxyPort;
    }

    public void setProxyPort(Integer proxyPort) {
        this.proxyPort = proxyPort;
    }

    void setUseProxy(String property) {
        Boolean value = Boolean.valueOf(property);
        setUseProxy(value);
    }

    void setProxyPort(String property) {
        Integer value = Integer.valueOf(property);
        setProxyPort(value);
    }

}

/**
 * Тип - респондета юрик или физик
 * @author Rustem.Zhunusov_at_gmail.com
 */
enum TypeOfRespondent {
    FIRM(1), PERSON(2);
    private final int code;
    TypeOfRespondent( int aCode){this.code = aCode;}    
    public int getCode(){ return code;}
    public static TypeOfRespondent findByCode(int seekCode){
        for (TypeOfRespondent seekType : TypeOfRespondent.values()){
            if (seekType.getCode() == seekCode){
                return  seekType;
            }
        }
        return null;
    }  
}

/**
 * Тип - текущее состояния загрузки CRL-файла 
 * @author Rustem.Zhunusov_at_gmail.com
 */
enum TypeOfCrlLoaded {
    NO_LOAD, LOADING, LOADED
}
