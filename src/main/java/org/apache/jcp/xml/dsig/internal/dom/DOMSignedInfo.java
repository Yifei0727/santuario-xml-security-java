/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright 2005 Sun Microsystems, Inc. All rights reserved.
 */
package org.apache.jcp.xml.dsig.internal.dom;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.TransformException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;

import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.UnsyncBufferedOutputStream;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * DOM-based implementation of SignedInfo.
 *
 */
public final class DOMSignedInfo extends DOMStructure implements SignedInfo {

    /**
     * The maximum number of references per Manifest, if secure validation is enabled.
     */
    public static final int MAXIMUM_REFERENCE_COUNT = 30;

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(DOMSignedInfo.class);

    /** Signature - NOT Recommended RSAwithMD5 */
    private static final String ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5 =
        Constants.MoreAlgorithmsSpecNS + "rsa-md5";

    /** HMAC - NOT Recommended HMAC-MD5 */
    private static final String ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5 =
        Constants.MoreAlgorithmsSpecNS + "hmac-md5";

    private final List<Reference> references;
    private final CanonicalizationMethod canonicalizationMethod;
    private final SignatureMethod signatureMethod;
    private String id;
    private Document ownerDoc;
    private Element localSiElem;
    private InputStream canonData;

    /**
     * Creates a <code>DOMSignedInfo</code> from the specified parameters. Use
     * this constructor when the <code>Id</code> is not specified.
     *
     * @param cm the canonicalization method
     * @param sm the signature method
     * @param references the list of references. The list is copied.
     * @throws NullPointerException if
     *    <code>cm</code>, <code>sm</code>, or <code>references</code> is
     *    <code>null</code>
     * @throws IllegalArgumentException if <code>references</code> is empty
     * @throws ClassCastException if any of the references are not of
     *    type <code>Reference</code>
     */
    public DOMSignedInfo(CanonicalizationMethod cm, SignatureMethod sm,
                         List<? extends Reference> references) {
        if (cm == null || sm == null || references == null) {
            throw new NullPointerException();
        }
        this.canonicalizationMethod = cm;
        this.signatureMethod = sm;
        this.references = Collections.unmodifiableList(new ArrayList<>(references));
        if (this.references.isEmpty()) {
            throw new IllegalArgumentException("list of references must contain at least one entry");
        }
        for (Object obj : this.references) {
            if (!(obj instanceof Reference)) {
                throw new ClassCastException("list of references contains an illegal " + obj.getClass());
            }
        }
    }

    /**
     * Creates a <code>DOMSignedInfo</code> from the specified parameters.
     *
     * @param cm the canonicalization method
     * @param sm the signature method
     * @param references the list of references. The list is copied.
     * @param id an optional identifer that will allow this
     *    <code>SignedInfo</code> to be referenced by other signatures and
     *    objects
     * @throws NullPointerException if <code>cm</code>, <code>sm</code>,
     *    or <code>references</code> is <code>null</code>
     * @throws IllegalArgumentException if <code>references</code> is empty
     * @throws ClassCastException if any of the references are not of
     *    type <code>Reference</code>
     */
    public DOMSignedInfo(CanonicalizationMethod cm, SignatureMethod sm,
                         List<? extends Reference> references, String id) {
        this(cm, sm, references);
        this.id = id;
    }

    /**
     * Creates a <code>DOMSignedInfo</code> from an element.
     *
     * @param siElem a SignedInfo element
     */
    public DOMSignedInfo(Element siElem, XMLCryptoContext context, Provider provider)
        throws MarshalException {
        localSiElem = siElem;
        ownerDoc = siElem.getOwnerDocument();

        // get Id attribute, if specified
        id = DOMUtils.getAttributeValue(siElem, "Id");

        // unmarshal CanonicalizationMethod
        Element cmElem = DOMUtils.getFirstChildElement(siElem,
                                                       "CanonicalizationMethod",
                                                       XMLSignature.XMLNS);
        canonicalizationMethod = new DOMCanonicalizationMethod(cmElem, context,
                                                               provider);

        // unmarshal SignatureMethod
        Element smElem = DOMUtils.getNextSiblingElement(cmElem,
                                                        "SignatureMethod",
                                                        XMLSignature.XMLNS);
        signatureMethod = DOMSignatureMethod.unmarshal(smElem);

        boolean secVal = Utils.secureValidation(context);

        String signatureMethodAlgorithm = signatureMethod.getAlgorithm();
        if (secVal && (ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5.equals(signatureMethodAlgorithm)
                || ALGO_ID_SIGNATURE_NOT_RECOMMENDED_RSA_MD5.equals(signatureMethodAlgorithm))) {
            throw new MarshalException(
                "It is forbidden to use algorithm " + signatureMethod + " when secure validation is enabled"
            );
        }

        // unmarshal References
        ArrayList<Reference> refList = new ArrayList<>(5);
        Element refElem = DOMUtils.getNextSiblingElement(smElem, "Reference", XMLSignature.XMLNS);
        refList.add(new DOMReference(refElem, context, provider));

        refElem = DOMUtils.getNextSiblingElement(refElem);
        while (refElem != null) {
            String name = refElem.getLocalName();
            String namespace = refElem.getNamespaceURI();
            if (!"Reference".equals(name) || !XMLSignature.XMLNS.equals(namespace)) {
                throw new MarshalException("Invalid element name: " +
                                           namespace + ":" + name + ", expected Reference");
            }
            refList.add(new DOMReference(refElem, context, provider));
            if (secVal && refList.size() > MAXIMUM_REFERENCE_COUNT) {
                String error = "A maxiumum of " + MAXIMUM_REFERENCE_COUNT + " "
                    + "references per Manifest are allowed with secure validation";
                throw new MarshalException(error);
            }
            refElem = DOMUtils.getNextSiblingElement(refElem);
        }
        references = Collections.unmodifiableList(refList);
    }

    @Override
    public CanonicalizationMethod getCanonicalizationMethod() {
        return canonicalizationMethod;
    }

    @Override
    public SignatureMethod getSignatureMethod() {
        return signatureMethod;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public List<Reference> getReferences() {
        return references;
    }

    @Override
    public InputStream getCanonicalizedData() {
        return canonData;
    }

    public void canonicalize(XMLCryptoContext context, ByteArrayOutputStream bos)
        throws XMLSignatureException {
        if (context == null) {
            throw new NullPointerException("context cannot be null");
        }

        DOMSubTreeData subTree = new DOMSubTreeData(localSiElem, true);
        try (OutputStream os = new UnsyncBufferedOutputStream(bos)) {
            ((DOMCanonicalizationMethod)
                canonicalizationMethod).canonicalize(subTree, context, os);

            os.flush();

            byte[] signedInfoBytes = bos.toByteArray();

            // this whole block should only be done if LOGging is enabled
            if (LOG.isDebugEnabled()) {
                LOG.debug("Canonicalized SignedInfo:");
                StringBuilder sb = new StringBuilder(signedInfoBytes.length);
                for (byte signedInfoByte : signedInfoBytes) {
                    sb.append((char) signedInfoByte);
                }
                LOG.debug(sb.toString());
                LOG.debug("Data to be signed/verified:" + XMLUtils.encodeToString(signedInfoBytes));
            }

            this.canonData = new ByteArrayInputStream(signedInfoBytes);
        } catch (TransformException te) {
            throw new XMLSignatureException(te);
        } catch (IOException e) {
            LOG.debug(e.getMessage(), e);
            // Impossible
        }
    }

    @Override
    public void marshal(Node parent, String dsPrefix, DOMCryptoContext context)
        throws MarshalException
    {
        ownerDoc = DOMUtils.getOwnerDocument(parent);
        Element siElem = DOMUtils.createElement(ownerDoc, "SignedInfo",
                                                XMLSignature.XMLNS, dsPrefix);

        // create and append CanonicalizationMethod element
        DOMCanonicalizationMethod dcm =
            (DOMCanonicalizationMethod)canonicalizationMethod;
        dcm.marshal(siElem, dsPrefix, context);

        // create and append SignatureMethod element
        ((DOMStructure)signatureMethod).marshal(siElem, dsPrefix, context);

        // create and append Reference elements
        for (Reference reference : references) {
            ((DOMReference)reference).marshal(siElem, dsPrefix, context);
        }

        // append Id attribute
        DOMUtils.setAttributeID(siElem, "Id", id);

        parent.appendChild(siElem);
        localSiElem = siElem;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }

        if (!(o instanceof SignedInfo)) {
            return false;
        }
        SignedInfo osi = (SignedInfo)o;

        boolean idEqual = id == null ? osi.getId() == null
                                      : id.equals(osi.getId());

        return canonicalizationMethod.equals(osi.getCanonicalizationMethod())
                && signatureMethod.equals(osi.getSignatureMethod()) &&
                references.equals(osi.getReferences()) && idEqual;
    }

    @SuppressWarnings("unchecked")
    public static List<Reference> getSignedInfoReferences(SignedInfo si) {
        return si.getReferences();
    }

    @Override
    public int hashCode() {
        int result = 17;
        if (id != null) {
            result = 31 * result + id.hashCode();
        }
        result = 31 * result + canonicalizationMethod.hashCode();
        result = 31 * result + signatureMethod.hashCode();
        result = 31 * result + references.hashCode();

        return result;
    }
}
