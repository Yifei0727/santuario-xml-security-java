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
package org.apache.xml.security.stax.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import javax.xml.stream.XMLStreamException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of a InputProcessorChain
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class InputProcessorChainImpl implements InputProcessorChain {

    protected static final transient Log log = LogFactory.getLog(InputProcessorChainImpl.class);
    protected static final transient boolean isDebugEnabled = log.isDebugEnabled();

    private List<InputProcessor> inputProcessors;
    private int startPos = 0;
    private int curPos = 0;

    private final SecurityContext securityContext;
    private final DocumentContextImpl documentContext;

    public InputProcessorChainImpl(SecurityContext securityContext) {
        this(securityContext, 0);
    }

    public InputProcessorChainImpl(SecurityContext securityContext, int startPos) {
        this(securityContext, new DocumentContextImpl(), startPos, new ArrayList<InputProcessor>(20));
    }

    public InputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContext) {
        this(securityContext, documentContext, 0, new ArrayList<InputProcessor>(20));
    }

    protected InputProcessorChainImpl(SecurityContext securityContext, DocumentContextImpl documentContextImpl,
                                      int startPos, List<InputProcessor> inputProcessors) {
        this.securityContext = securityContext;
        this.curPos = this.startPos = startPos;
        this.documentContext = documentContextImpl;
        this.inputProcessors = inputProcessors;
    }

    public void reset() {
        this.curPos = startPos;
    }

    public SecurityContext getSecurityContext() {
        return this.securityContext;
    }

    public DocumentContext getDocumentContext() {
        return this.documentContext;
    }

    public synchronized void addProcessor(InputProcessor newInputProcessor) {
        int startPhaseIdx = 0;
        int endPhaseIdx = inputProcessors.size();

        XMLSecurityConstants.Phase targetPhase = newInputProcessor.getPhase();

        for (int i = inputProcessors.size() - 1; i >= 0; i--) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() > targetPhase.ordinal()) {
                startPhaseIdx = i + 1;
                break;
            }
        }
        for (int i = startPhaseIdx; i < inputProcessors.size(); i++) {
            InputProcessor inputProcessor = inputProcessors.get(i);
            if (inputProcessor.getPhase().ordinal() < targetPhase.ordinal()) {
                endPhaseIdx = i;
                break;
            }
        }

        //just look for the correct phase and append as last
        if (newInputProcessor.getBeforeProcessors().isEmpty()
                && newInputProcessor.getAfterProcessors().isEmpty()) {
            inputProcessors.add(startPhaseIdx, newInputProcessor);
        } else if (newInputProcessor.getBeforeProcessors().isEmpty()) {
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getAfterProcessors().contains(inputProcessor)
                        || newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else if (newInputProcessor.getAfterProcessors().isEmpty()) {
            int idxToInsert = endPhaseIdx;

            for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getBeforeProcessors().contains(inputProcessor)
                        || newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i + 1;
                    break;
                }
            }
            inputProcessors.add(idxToInsert, newInputProcessor);
        } else {
            boolean found = false;
            int idxToInsert = startPhaseIdx;

            for (int i = endPhaseIdx - 1; i >= startPhaseIdx; i--) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                if (newInputProcessor.getAfterProcessors().contains(inputProcessor)
                        || newInputProcessor.getAfterProcessors().contains(inputProcessor.getClass().getName())) {
                    idxToInsert = i;
                    found = true;
                    break;
                }
            }
            if (found) {
                inputProcessors.add(idxToInsert, newInputProcessor);
            } else {
                for (int i = startPhaseIdx; i < endPhaseIdx; i++) {
                    InputProcessor inputProcessor = inputProcessors.get(i);
                    if (newInputProcessor.getBeforeProcessors().contains(inputProcessor)
                            || newInputProcessor.getBeforeProcessors().contains(inputProcessor.getClass().getName())) {
                        idxToInsert = i + 1;
                        break;
                    }
                }
                inputProcessors.add(idxToInsert, newInputProcessor);
            }
        }
        if (isDebugEnabled) {
            log.debug("Added " + newInputProcessor.getClass().getName() + " to input chain: ");
            for (int i = 0; i < inputProcessors.size(); i++) {
                InputProcessor inputProcessor = inputProcessors.get(i);
                log.debug("Name: " + inputProcessor.getClass().getName() + " phase: " + inputProcessor.getPhase());
            }
        }
    }

    public synchronized void removeProcessor(InputProcessor inputProcessor) {
        if (isDebugEnabled) {
            log.debug("Removing processor " + inputProcessor.getClass().getName() + " from input chain");
        }
        if (this.inputProcessors.indexOf(inputProcessor) <= curPos) {
            this.curPos--;
        }
        this.inputProcessors.remove(inputProcessor);
    }

    public List<InputProcessor> getProcessors() {
        return this.inputProcessors;
    }

    public XMLSecEvent processHeaderEvent() throws XMLStreamException, XMLSecurityException {
        return inputProcessors.get(this.curPos++).processNextHeaderEvent(this);
    }

    public XMLSecEvent processEvent() throws XMLStreamException, XMLSecurityException {
        return inputProcessors.get(this.curPos++).processNextEvent(this);
    }

    public void doFinal() throws XMLStreamException, XMLSecurityException {
        inputProcessors.get(this.curPos++).doFinal(this);
    }

    public InputProcessorChain createSubChain(InputProcessor inputProcessor) throws XMLStreamException, XMLSecurityException {
        InputProcessorChainImpl inputProcessorChain;
        try {
            inputProcessorChain = new InputProcessorChainImpl(securityContext, documentContext.clone(),
                    inputProcessors.indexOf(inputProcessor) + 1, new ArrayList<InputProcessor>(this.inputProcessors));
        } catch (CloneNotSupportedException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
        }
        return inputProcessorChain;
    }
}
