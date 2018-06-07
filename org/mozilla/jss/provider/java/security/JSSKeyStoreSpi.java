/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.jss.provider.java.security;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.CryptoManager.NotInitializedException;
import org.mozilla.jss.NoSuchTokenException;
import org.mozilla.jss.crypto.CryptoStore;
import org.mozilla.jss.crypto.CryptoToken;
import org.mozilla.jss.crypto.ObjectNotFoundException;
import org.mozilla.jss.crypto.PrivateKey;
import org.mozilla.jss.crypto.SecretKeyFacade;
import org.mozilla.jss.crypto.SymmetricKey;
import org.mozilla.jss.crypto.TokenException;
import org.mozilla.jss.crypto.TokenRuntimeException;
import org.mozilla.jss.crypto.TokenSupplierManager;
import org.mozilla.jss.crypto.X509Certificate;
import org.mozilla.jss.pkcs11.PK11Token;
import org.mozilla.jss.pkcs11.TokenProxy;
import org.mozilla.jss.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.security.x509.X509CertImpl;

/**
 * The JSS implementation of the JCA KeyStore SPI.
 *
 * <p>Implementation notes
 * <ol>
 * <li>deleteEntry will delete all entries with that label. If the entry is a
 * cert with a matching private key, it will also delete the private key.
 *
 * <li>getCertificate returns first cert with matching nickname. Converts it
 * into a java.security.cert.X509Certificate (not a JSS cert).
 *
 * <li>getCertificateChain only returns a single certificate. That's because
 * we don't have a way to build a chain from a specific slot--only from
 * the set of all slots.
 *
 * <li>getCreationDate is unsupported because NSS doesn't store that
 * information.
 *
 * <li>getKey first looks for a private/symmetric key with the given label.
 * It returns the first one it finds. If it doesn't find one, it looks for a
 * cert with the given nickname. If it finds one, it returns the private key
 * for that cert.
 *
 * <li>isCertificateEntry returns true if there is a cert with this nickname,
 * but it doesn't have a private key. isKeyEntry returns true if there is a key
 * with this nickname, or if there is a cert with this nickname and the cert
 * has an associated private key.
 *
 * <li>load and store are no-ops.
 *
 * <li>setCertificateEntry doesn't work.NSS doesn't have a way of storing a
 * certificate on a specific token unless it has an associated private key.
 * That rules out trusted certificate entries.
 *
 * <li>setKeyEntry not supported yet. Need to convert a temporary key
 * into a permanent key.
 * </ol>
 */
public class JSSKeyStoreSpi extends java.security.KeyStoreSpi {

    public static Logger logger = LoggerFactory.getLogger(JSSKeyStoreSpi.class);

    protected TokenProxy proxy;

    public JSSKeyStoreSpi() throws TokenException {

        logger.debug("JSSKeyStoreSpi: initialization");

        CryptoToken token =
            TokenSupplierManager.getTokenSupplier().getThreadToken();
        logger.debug("JSSKeyStoreSpi: token: " + token.getName());

        PK11Token pk11tok = (PK11Token)token;
        proxy = pk11tok.getProxy();
    }

    /**
     * Converts an Iterator into an Enumeration.
     */
    private static class IteratorEnumeration<T> implements Enumeration<T> {
        private Iterator<T> iter;

        public IteratorEnumeration(Iterator<T> iter) {
            this.iter = iter;
        }

        public boolean hasMoreElements() {
            return iter.hasNext();
        }

        public T nextElement() {
            return iter.next();
        }
    }

    private native HashSet<String> getRawAliases();

    /**
     * Returns a list of unique aliases.
     */
    public Enumeration<String> engineAliases() {

        logger.debug("JSSKeyStoreSpi: engineAliases()");
        new Exception().printStackTrace();

        Set<String> aliases = new LinkedHashSet<>();

        try {
            CryptoManager cm = CryptoManager.getInstance();

            logger.debug("JSSKeyStoreSpi: calling CryptoManager.getAllTokens()");
            Enumeration<CryptoToken> tokens = cm.getAllTokens();

            while (tokens.hasMoreElements()) {
                CryptoToken token = tokens.nextElement();

                if (token == cm.getInternalCryptoToken()) {
                    continue;
                }

                String tokenName;
                if (token == cm.getInternalKeyStorageToken()) {
                    tokenName = null;
                    logger.debug("JSSKeyStoreSpi: Internal token");
                } else {
                    tokenName = token.getName();
                    logger.debug("JSSKeyStoreSpi: Token " + tokenName);
                }


                CryptoStore store = token.getCryptoStore();

                logger.debug("JSSKeyStoreSpi: - certificates:");
                for (X509Certificate cert : store.getCertificates()) {
                    String nickname = cert.getNickname();
                    logger.debug("JSSKeyStoreSpi:   - " + nickname);
                    aliases.add(nickname);
                }

                logger.debug("JSSKeyStoreSpi: - private keys:");
                for (PrivateKey privateKey : store.getPrivateKeys()) {
                    String nickname = Util.bytesToHex(privateKey.getUniqueID());
                    if (tokenName != null) {
                        nickname = tokenName + ":" + nickname;
                    }
                    logger.debug("JSSKeyStoreSpi:   - " + nickname);
                    aliases.add(nickname);
                }
            }

            return new IteratorEnumeration<String>( aliases.iterator() );

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean engineContainsAlias(String alias) {

        logger.debug("JSSKeyStoreSpi: engineContainsAlias(" + alias + ")");

        return getRawAliases().contains(alias);
    }

    public native void engineDeleteEntry(String alias);

    /*
     * XXX-!!! Is shared cert factory thread safe?
     */
    private CertificateFactory certFactory=null;
    {
      try {
        certFactory = CertificateFactory.getInstance("X.509");
      } catch(CertificateException e) {
        e.printStackTrace();
        throw new RuntimeException(e.getMessage());
      }
    }

    public Certificate engineGetCertificate(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificate(" + alias + ")");

        try {
            CryptoManager cm = CryptoManager.getInstance();
            X509Certificate cert = cm.findCertByNickname(alias);

            logger.debug("JSSKeyStoreSpi: cert found");
            return new X509CertImpl(cert.getEncoded());

        } catch (ObjectNotFoundException e) {
            logger.debug("JSSKeyStoreSpi: cert not found");
            return null;

        } catch (NotInitializedException e) {
            throw new RuntimeException(e);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    private native byte[] getDERCert(String alias);
    private native X509Certificate getCertObject(String alias);

    public String engineGetCertificateAlias(Certificate cert) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificateAlias()");

      try {
        return getCertNickname( cert.getEncoded() );
      } catch(CertificateEncodingException e) {
        return null;
      }
    }

    private native String getCertNickname(byte[] derCert);

    public Certificate[] engineGetCertificateChain(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCertificateChain(" + alias + ")");

      try {
        X509Certificate leaf = getCertObject(alias);
        if( leaf == null ) {
            return null;
        }
        CryptoManager cm = CryptoManager.getInstance();
        X509Certificate[] jssChain = cm.buildCertificateChain(leaf);

        Certificate[] chain = new Certificate[jssChain.length];
        for( int i=0; i < chain.length; ++i) {
            chain[i] = certFactory.generateCertificate(
                        new ByteArrayInputStream(jssChain[i].getEncoded()) );
        }
        return chain;
      } catch(TokenException te ) {
            throw new TokenRuntimeException(te.toString());
      } catch(CryptoManager.NotInitializedException e) {
            throw new RuntimeException("CryptoManager not initialized");
      } catch(CertificateException ce) {
            ce.printStackTrace();
            return null;
      }
    }

    /*
     * Not supported.
     */
    public java.util.Date engineGetCreationDate(String alias) {

        logger.debug("JSSKeyStoreSpi: engineGetCreationDate(" + alias + ")");

        return null;
    }

    public Key engineGetKey(String alias, char[] password) {

        logger.debug("JSSKeyStoreSpi: engineGetKey(" + alias + ")");

        try {
            String nickname;
            String tokenName;

            String[] parts = alias.split(":");
            if (parts.length == 1) {
                tokenName = null;
                nickname = parts[0];
            } else {
                tokenName = parts[0];
                nickname = parts[1];
            }

            logger.debug("JSSKeyStoreSpi: token: " + tokenName);
            logger.debug("JSSKeyStoreSpi: nickname: " + nickname);

            //Object o = engineGetKeyNative(alias, password);

            CryptoManager cm = CryptoManager.getInstance();

            try {
                X509Certificate cert = cm.findCertByNickname(alias);
                logger.debug("JSSKeyStoreSpi: found certificate with alias " + alias);

                PrivateKey privateKey = cm.findPrivKeyByCert(cert);
                if (privateKey != null) {
                    logger.debug("JSSKeyStoreSpi: algorithm: " + privateKey.getAlgorithm());
                    return privateKey;
                }

            } catch (ObjectNotFoundException e) {
                logger.debug("JSSKeyStoreSpi: no certificate with alias " + alias);
            }

            CryptoToken token;
            if (tokenName == null) {
                token = cm.getInternalKeyStorageToken();
            } else {
                token = cm.getTokenByName(tokenName);
            }

            logger.debug("JSSKeyStoreSpi: finding key with nickname " + nickname);

            CryptoStore store = token.getCryptoStore();
            Key[] keys = store.getPrivateKeys();
            if (keys.length == 0) {
                logger.debug("JSSKeyStoreSpi: key not found");
                return null;
            }

            for (Key key : keys) {

                logger.debug("JSSKeyStoreSpi: - algorithm: " + key.getAlgorithm());

                if( key instanceof SymmetricKey ) {
                    SymmetricKey symmetricKey = (SymmetricKey)key;
                    logger.debug("JSSKeyStoreSpi:   nickname: " + symmetricKey.getNickName());
                    return new SecretKeyFacade(symmetricKey);

                } else if( key instanceof PrivateKey ) {
                    PrivateKey privateKey = (PrivateKey) key;
                    String n = Util.bytesToHex(privateKey.getUniqueID());
                    if (nickname.equals(n)) {
                        return key;
                    }
                }
            }

            return null;

        } catch (NoSuchTokenException e) {
            throw new RuntimeException(e);
        } catch (NotInitializedException e) {
            throw new RuntimeException(e);
        } catch (TokenException e) {
            throw new RuntimeException(e);
        }
    }

    public native Object engineGetKeyNative(String alias, char[] password);

    /**
     * Returns true if there is a cert with this nickname but there is no
     * key associated with the cert.
     */
    public boolean engineIsCertificateEntry(String alias) {
        logger.debug("JSSKeyStoreSpi: engineIsCertificateEntry(" + alias + ")");
        return engineGetCertificate(alias) != null;
    }

    public native boolean engineIsCertificateEntryNative(String alias);

    /**
     * Returns true if there is a key with this alias, or if
     * there is a cert with this alias that has an associated key.
     */
    public boolean engineIsKeyEntry(String alias) {

        logger.debug("JSSKeyStoreSpi: engineIsKeyEntry(" + alias + ")");

        /* this is somewhat wasteful but we can speed it up later */
        return ( engineGetKey(alias, null) != null );
    }

    public void engineLoad(InputStream stream, char[] password)
        throws IOException
    {
        logger.debug("JSSKeyStoreSpi: engineLoad()");
    }

    /**
     * NSS doesn't have a way of storing a certificate on a specific token
     * unless it has an associated private key.  That rules out
     * trusted certificate entries, so we can't supply this method currently.
     */
    public void engineSetCertificateEntry(String alias, Certificate cert)
            throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetCertificateEntry(" + alias + ")");

        throw new KeyStoreException(
            "Storing trusted certificate entries to a JSS KeyStore is not" +
            " supported.");
    }


    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
        throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetKeyEntry(" + alias + ", key, chain)");

        throw new KeyStoreException("Storing plaintext keys is not supported."+
            "Store the key as a handle instead.");
    }

    public void engineSetKeyEntry(String alias, Key key, char[] password,
        Certificate[] chain) throws KeyStoreException
    {

        logger.debug("JSSKeyStoreSpi: engineSetKeyEntry(" + alias + ", key, password, chain)");

        if( key instanceof SecretKeyFacade ) {
            SecretKeyFacade skf = (SecretKeyFacade)key;
            engineSetKeyEntryNative(alias, skf.key, password, chain);
        } else {
            engineSetKeyEntryNative(alias, key, password, chain);
        }
    }

    private native void engineSetKeyEntryNative(String alias, Object key,
        char[] password, Certificate[] chain) throws KeyStoreException;

    public int engineSize() {

        logger.debug("JSSKeyStoreSpi: engineSize()");

        return getRawAliases().size();
    }

    public void engineStore(OutputStream stream, char[] password)
            throws IOException
    {
        logger.debug("JSSKeyStoreSpi: engineStore()");
    }
}
