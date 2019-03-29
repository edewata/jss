package org.mozilla.jss.pkcs11;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;

import org.mozilla.jss.crypto.PrivateKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PK11ECPrivateKey
    extends PK11PrivKey implements ECPrivateKey
{
    public static Logger logger = LoggerFactory.getLogger(PK11ECPrivateKey.class);

    private static final long serialVersionUID = 1L;

    private PK11ECPrivateKey() { super(null); }

    protected PK11ECPrivateKey(byte[] pointer) {
        super(pointer);
    }

    public PrivateKey.Type getType() {
        return PrivateKey.Type.EC;
    }

    @Override
    public ECParameterSpec getParams() {
        logger.debug("PK11ECPrivateKey: getParams()", new Exception());
        return null;
    }

    @Override
    public BigInteger getS() {
        logger.debug("PK11ECPrivateKey: getS()", new Exception());
        return null;
    }

    /**
     * If this fails, we just return null, since no exceptions are allowed.
     */
// requires JAVA 1.5
//    public ECParams getParams() {
//      try {
//        return getECParams();
//      } catch(TokenException te) {
//            return null;
//      }
//    }

    /**
     * Not implemented. NSS doesn't support extracting private key material
     * like this.
     */
// requires JAVA 1.5
//    public BigInteger getW() {
//        return null;
//    }
}
