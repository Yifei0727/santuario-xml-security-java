package org.apache.xml.security.keys.content.keyvalues;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.I18n;
import org.apache.xml.security.utils.SignatureElementProxy;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.crypto.MarshalException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.*;
import java.util.Arrays;

public class SM2KeyValue extends SignatureElementProxy implements KeyValueContent {

    public SM2KeyValue(Element element, String baseURI) throws XMLSecurityException {
        super(element, baseURI);
    }

    ECPublicKey ecPublicKey;

    /**
     * Constructor KeyValue
     *
     * @param doc
     * @param key
     * @throws IllegalArgumentException
     */
    public SM2KeyValue(Document doc, Key key) throws IllegalArgumentException {
        super(doc);

        addReturnToSelf();

        if (key instanceof ECPublicKey) {
            ECParameterSpec ecParams = ((ECPublicKey) key).getParams();
            ecPublicKey = (ECPublicKey) key;
            // NamedCurve
            final String oid = "1.2.156.10197.1.301";

            Element namedCurveElement = XMLUtils.createElementInSignature11Space(getDocument(), "NamedCurve");
            namedCurveElement.setAttributeNS(null, "URI", "urn:oid:" + oid);
            appendSelf(namedCurveElement);
            addReturnToSelf();

            // PublicKey
            ECPoint ecPoint = ((ECPublicKey) key).getW();
            byte[] secPublicKey = encodePoint(ecPoint, ecParams.getCurve());
            String encoded = XMLUtils.encodeToString(secPublicKey);
            Element publicKeyElement = XMLUtils.createElementInSignature11Space(getDocument(), "PublicKey");
            Text text = getDocument().createTextNode(encoded);

            publicKeyElement.appendChild(text);

            appendSelf(publicKeyElement);
            addReturnToSelf();

        } else {
            Object[] exArgs = {Constants._TAG_SM2KEYVALUE, key.getClass().getName()};

            throw new IllegalArgumentException(I18n.translate("KeyValue.IllegalArgument", exArgs));
        }
    }

    @Override
    public String getBaseLocalName() {
        return Constants._TAG_SM2KEYVALUE;
    }

    @Override
    public PublicKey getPublicKey() throws XMLSecurityException {
        try {
            ECParameterSpec ecParams = null;
            Element curElem = getFirstChildElement(getElement());
            if (curElem == null) {
                throw new MarshalException("KeyValue must contain at least one type");
            }

            if ("NamedCurve".equals(curElem.getLocalName())
                && Constants.SignatureSpec11NS.equals(curElem.getNamespaceURI())) {
                String uri = null;
                if (curElem.hasAttributeNS(null, "URI")) {
                    uri = curElem.getAttributeNS(null, "URI");
                }
                // strip off "urn:oid"
                if (uri != null && uri.startsWith("urn:oid:")) {
                    String oid = uri.substring("urn:oid:".length());
                    ecParams = getECParameterSpec(oid);
                    if (ecParams == null) {
                        throw new MarshalException("Invalid curve OID");
                    }
                } else {
                    throw new MarshalException("Invalid NamedCurve URI");
                }
            } else {
                throw new MarshalException("Invalid ECKeyValue");
            }
            curElem = getNextSiblingElement(curElem, "PublicKey", Constants.SignatureSpec11NS);
            ECPoint ecPoint = null;

            try {
                String content = XMLUtils.getFullTextChildrenFromNode(curElem);
                ecPoint = decodePoint(XMLUtils.decode(content), ecParams.getCurve());
            } catch (IOException ioe) {
                throw new MarshalException("Invalid EC Point", ioe);
            }

            ECPublicKeySpec spec = new ECPublicKeySpec(ecPoint, ecParams);
            return KeyFactory.getInstance("EC").generatePublic(spec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | MarshalException ex) {
            throw new XMLSecurityException(ex);
        }
    }

    private static final Curve sm2p256v1 = initializeCurve(
        "sm2p256v1",
        "1.2.156.10197.1.301",
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",// p,0
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",// a,1
        "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",// b,2
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",// Gx,4
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", // Gy,5
        "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",// n,3
        1
    );

    private ECParameterSpec getECParameterSpec(String oid) {
        if (sm2p256v1.getObjectId().equals(oid)) {
            return sm2p256v1;
        }
        return null;
    }


    private static byte[] trimZeroes(byte[] b) {
        int i = 0;
        while (i < b.length - 1 && b[i] == 0) {
            i++;
        }
        if (i == 0) {
            return b;
        }
        return Arrays.copyOfRange(b, i, b.length);
    }

    private static Element getFirstChildElement(Node node) {
        Node child = node.getFirstChild();
        while (child != null && child.getNodeType() != Node.ELEMENT_NODE) {
            child = child.getNextSibling();
        }
        return (Element) child;
    }

    private static Element getNextSiblingElement(Node node, String localName, String namespaceURI)
        throws MarshalException
    {
        return verifyElement(getNextSiblingElement(node), localName, namespaceURI);
    }

    private static Element getNextSiblingElement(Node node) {
        Node sibling = node.getNextSibling();
        while (sibling != null && sibling.getNodeType() != Node.ELEMENT_NODE) {
            sibling = sibling.getNextSibling();
        }
        return (Element) sibling;
    }

    private static Element verifyElement(Element elem, String localName, String namespaceURI)
        throws MarshalException
    {
        if (elem == null) {
            throw new MarshalException("Missing " + localName + " element");
        }
        String name = elem.getLocalName();
        String namespace = elem.getNamespaceURI();
        if (!name.equals(localName) || namespace == null && namespaceURI != null
            || namespace != null && !namespace.equals(namespaceURI)) {
            throw new MarshalException("Invalid element name: " +
                namespace + ":" + name + ", expected " + namespaceURI + ":" + localName);
        }
        return elem;
    }

    private static BigInteger bigInt(String s) {
        return new BigInteger(s, 16);
    }

    private static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        // get field size in bytes (rounding up)
        int n = (curve.getField().getFieldSize() + 7) >> 3;
        byte[] xb = trimZeroes(point.getAffineX().toByteArray());
        byte[] yb = trimZeroes(point.getAffineY().toByteArray());
        if (xb.length > n || yb.length > n) {
            throw new RuntimeException("Point coordinates do not " +
                "match field size");
        }
        byte[] b = new byte[1 + (n << 1)];
        b[0] = 4; // uncompressed
        System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
        System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
        return b;
    }

    private static ECPoint decodePoint(byte[] data, EllipticCurve curve)
        throws IOException
    {
        if (data.length == 0 || data[0] != 4) {
            throw new IOException("Only uncompressed point format " +
                "supported");
        }
        // Per ANSI X9.62, an encoded point is a 1 byte type followed by
        // ceiling(LOG base 2 field-size / 8) bytes of x and the same of y.
        int n = (data.length - 1) / 2;
        if (n != (curve.getField().getFieldSize() + 7) >> 3) {
            throw new IOException("Point does not match field size");
        }

        byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
        byte[] yb = Arrays.copyOfRange(data, n + 1, n + 1 + n);

        return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
    }

    static final class Curve extends ECParameterSpec {
        private final String name;
        private final String oid;

        Curve(String name, String oid, EllipticCurve curve,
              ECPoint g, BigInteger n, int h)
        {
            super(curve, g, n, h);
            this.name = name;
            this.oid = oid;
        }

        private String getName() {
            return name;
        }

        private String getObjectId() {
            return oid;
        }
    }

    private static Curve initializeCurve(String name, String oid,
                                         String sfield, String a, String b,
                                         String x, String y, String n, int h)
    {
        BigInteger p = bigInt(sfield);
        ECField field = new ECFieldFp(p);
        EllipticCurve curve = new EllipticCurve(field, bigInt(a),
            bigInt(b));
        ECPoint g = new ECPoint(bigInt(x), bigInt(y));
        return new Curve(name, oid, curve, g, bigInt(n), h);
    }


}
