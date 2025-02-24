package org.mozilla.jss.provider.javax.net;

import java.security.KeyManagementException;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.mozilla.jss.provider.javax.crypto.JSSKeyManager;
import org.mozilla.jss.ssl.SSLVersion;
import org.mozilla.jss.ssl.javax.JSSEngine;
import org.mozilla.jss.ssl.javax.JSSEngineReferenceImpl;
import org.mozilla.jss.ssl.javax.JSSParameters;
import org.mozilla.jss.ssl.javax.JSSServerSocketFactory;
import org.mozilla.jss.ssl.javax.JSSSocketFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JSSContextSpi extends SSLContextSpi {
    public static Logger logger = LoggerFactory.getLogger(JSSContextSpi.class);

    JSSKeyManager key_manager;
    X509TrustManager[] trust_managers;

    SSLVersion protocol_version;

    @Override
    public void engineInit(KeyManager[] kms, TrustManager[] tms, SecureRandom sr) throws KeyManagementException {
        logger.warn("JSSContextSpi.engineInit(" + kms + ", " + tms + ", " + sr + ")");

        if (kms != null) {
            for (KeyManager km : kms) {
                if (km instanceof JSSKeyManager) {
                    key_manager = (JSSKeyManager) km;
                    break;
                }
            }
        }

        if (tms != null) {
            ArrayList<X509TrustManager> xtms = new ArrayList<>();
            for (TrustManager tm : tms) {
                if (tm instanceof X509TrustManager) {
                    xtms.add((X509TrustManager) tm);
                }
            }

            trust_managers = xtms.toArray(new X509TrustManager[xtms.size()]);
        }
    }

    @Override
    public SSLEngine engineCreateSSLEngine() {
        logger.warn("JSSContextSpi.engineCreateSSLEngine()");

        JSSEngine ret = new JSSEngineReferenceImpl();
        initializeEngine(ret);

        return ret;
    }

    @Override
    public SSLEngine engineCreateSSLEngine(String host, int port) {
        logger.warn("JSSContextSpi.engineCreateSSLEngine(" + host + ", " + port + ")");

        JSSEngine ret = new JSSEngineReferenceImpl(host, port);
        initializeEngine(ret);

        return ret;
    }

    private void initializeEngine(JSSEngine eng) {
        eng.setKeyManager(key_manager);
        eng.setTrustManagers(trust_managers);

        if (protocol_version != null) {
            eng.setEnabledProtocols(protocol_version, protocol_version);
        }
    }

    @Override
    public SSLSessionContext engineGetClientSessionContext() {
        logger.warn("JSSContextSpi.engineGetClientSessionContext() - not implemented");
        return null;
    }

    @Override
    public SSLSessionContext engineGetServerSessionContext() {
        logger.warn("JSSContextSpi.engineGetServerSessionContext() - not implemented");
        return null;
    }

    @Override
    public SSLServerSocketFactory engineGetServerSocketFactory() {
        String protocol = "TLS";
        if (protocol_version != null) {
            protocol = protocol_version.jdkAlias();
        }

        logger.warn("JSSContextSpi.engineGetServerSocketFactory() @ " + protocol);
        return new JSSServerSocketFactory(protocol, key_manager, trust_managers);
    }

    @Override
    public SSLSocketFactory engineGetSocketFactory() {
        String protocol = "TLS";
        if (protocol_version != null) {
            protocol = protocol_version.jdkAlias();
        }

        logger.warn("JSSContextSpi.engineGetSocketFactory() @ " + protocol);
        return new JSSSocketFactory(protocol, key_manager, trust_managers);
    }

    @Override
    public SSLParameters engineGetSupportedSSLParameters() {
        JSSParameters params = new JSSParameters();
        params.setCipherSuites(JSSEngine.queryEnabledCipherSuites());
        params.setProtocols(JSSEngine.queryEnabledProtocols());
        return params;
    }

    public class TLSv11 extends JSSContextSpi {
        public TLSv11() {
            protocol_version = SSLVersion.TLS_1_1;
        }
    }

    public class TLSv12 extends JSSContextSpi {
        public TLSv12() {
            protocol_version = SSLVersion.TLS_1_2;
        }
    }

    public class TLSv13 extends JSSContextSpi {
        public TLSv13() {
            protocol_version = SSLVersion.TLS_1_3;
        }
    }
}
