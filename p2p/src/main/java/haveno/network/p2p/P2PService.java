/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package haveno.network.p2p;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.util.concurrent.FutureCallback;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.common.util.concurrent.SettableFuture;
import com.google.inject.Inject;
import haveno.common.UserThread;
import haveno.common.app.Capabilities;
import haveno.common.crypto.CryptoException;
import haveno.common.crypto.KeyRing;
import haveno.common.crypto.PubKeyRing;
import haveno.common.proto.ProtobufferException;
import haveno.common.proto.network.NetworkEnvelope;
import haveno.network.Socks5ProxyProvider;
import haveno.network.crypto.EncryptionService;
import haveno.network.p2p.mailbox.MailboxMessageService;
import haveno.network.p2p.network.CloseConnectionReason;
import haveno.network.p2p.network.Connection;
import haveno.network.p2p.network.ConnectionListener;
import haveno.network.p2p.network.MessageListener;
import haveno.network.p2p.network.NetworkNode;
import haveno.network.p2p.network.SetupListener;
import haveno.network.p2p.peers.Broadcaster;
import haveno.network.p2p.peers.PeerManager;
import haveno.network.p2p.peers.getdata.RequestDataManager;
import haveno.network.p2p.peers.keepalive.KeepAliveManager;
import haveno.network.p2p.peers.peerexchange.PeerExchangeManager;
import haveno.network.p2p.storage.HashMapChangedListener;
import haveno.network.p2p.storage.P2PDataStorage;
import haveno.network.p2p.storage.messages.RefreshOfferMessage;
import haveno.network.p2p.storage.payload.PersistableNetworkPayload;
import haveno.network.p2p.storage.payload.ProtectedStorageEntry;
import haveno.network.p2p.storage.payload.ProtectedStoragePayload;
import haveno.network.utils.CapabilityUtils;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ReadOnlyIntegerProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleIntegerProperty;
import lombok.Getter;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;
import org.fxmisc.easybind.monadic.MonadicBinding;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;

public class P2PService implements SetupListener, MessageListener, ConnectionListener, RequestDataManager.Listener {
    private static final Logger log = LoggerFactory.getLogger(P2PService.class);

    private final EncryptionService encryptionService;
    private final KeyRing keyRing;
    @Getter
    private final MailboxMessageService mailboxMessageService;

    private final NetworkNode networkNode;
    private final PeerManager peerManager;
    @Getter
    private final Broadcaster broadcaster;
    private final P2PDataStorage p2PDataStorage;
    private final RequestDataManager requestDataManager;
    private final PeerExchangeManager peerExchangeManager;

    @SuppressWarnings("FieldCanBeLocal")
    private final MonadicBinding<Boolean> networkReadyBinding;
    private final Set<DecryptedDirectMessageListener> decryptedDirectMessageListeners = new CopyOnWriteArraySet<>();
    private final Set<P2PServiceListener> p2pServiceListeners = new CopyOnWriteArraySet<>();
    private final Set<Runnable> shutDownResultHandlers = new CopyOnWriteArraySet<>();
    private final BooleanProperty hiddenServicePublished = new SimpleBooleanProperty();
    private final BooleanProperty preliminaryDataReceived = new SimpleBooleanProperty();
    private final IntegerProperty numConnectedPeers = new SimpleIntegerProperty(0);

    private final Subscription networkReadySubscription;
    private boolean isBootstrapped;
    private final KeepAliveManager keepAliveManager;
    private final Socks5ProxyProvider socks5ProxyProvider;

    @Getter
    private static NodeAddress myNodeAddress;
    @Getter
    private boolean isShutDownStarted = false;


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    ///////////////////////////////////////////////////////////////////////////////////////////

    // Called also from SeedNodeP2PService
    @Inject
    public P2PService(NetworkNode networkNode,
                      PeerManager peerManager,
                      P2PDataStorage p2PDataStorage,
                      RequestDataManager requestDataManager,
                      PeerExchangeManager peerExchangeManager,
                      KeepAliveManager keepAliveManager,
                      Broadcaster broadcaster,
                      Socks5ProxyProvider socks5ProxyProvider,
                      EncryptionService encryptionService,
                      KeyRing keyRing,
                      MailboxMessageService mailboxMessageService) {
        this.networkNode = networkNode;
        this.peerManager = peerManager;
        this.p2PDataStorage = p2PDataStorage;
        this.requestDataManager = requestDataManager;
        this.peerExchangeManager = peerExchangeManager;
        this.keepAliveManager = keepAliveManager;
        this.broadcaster = broadcaster;
        this.socks5ProxyProvider = socks5ProxyProvider;
        this.encryptionService = encryptionService;
        this.keyRing = keyRing;
        this.mailboxMessageService = mailboxMessageService;

        this.networkNode.addConnectionListener(this);
        this.networkNode.addMessageListener(this);
        this.requestDataManager.setListener(this);

        // We need to have both the initial data delivered and the hidden service published
        networkReadyBinding = EasyBind.combine(hiddenServicePublished, preliminaryDataReceived,
                (hiddenServicePublished, preliminaryDataReceived) -> hiddenServicePublished && preliminaryDataReceived);
        networkReadySubscription = networkReadyBinding.subscribe((observable, oldValue, newValue) -> {
            if (newValue)
                onNetworkReady();
        });
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // API
    ///////////////////////////////////////////////////////////////////////////////////////////

    public void start(@Nullable P2PServiceListener listener) {
        if (listener != null)
            addP2PServiceListener(listener);

        networkNode.start(this);
    }

    public void onAllServicesInitialized() {
        if (networkNode.getNodeAddress() != null) {
            myNodeAddress = networkNode.getNodeAddress();
        } else {
            // If our HS is still not published
            networkNode.nodeAddressProperty().addListener((observable, oldValue, newValue) -> {
                if (newValue != null) {
                    myNodeAddress = networkNode.getNodeAddress();
                }
            });
        }
    }

    public void shutDown(Runnable shutDownCompleteHandler) {
        log.info("P2PService shutdown started");
        shutDownResultHandlers.add(shutDownCompleteHandler);

        // We need to make sure queued up messages are flushed out before we continue shut down other network
        // services
        if (broadcaster != null) {
            broadcaster.shutDown(this::doShutDown);
        } else {
            doShutDown();
        }
    }

    private void doShutDown() {
        log.info("P2PService doShutDown started");
        isShutDownStarted = true;

        if (p2PDataStorage != null) {
            p2PDataStorage.shutDown();
        }

        if (peerManager != null) {
            peerManager.shutDown();
        }

        if (requestDataManager != null) {
            requestDataManager.shutDown();
        }

        if (peerExchangeManager != null) {
            peerExchangeManager.shutDown();
        }

        if (keepAliveManager != null) {
            keepAliveManager.shutDown();
        }

        if (networkReadySubscription != null) {
            networkReadySubscription.unsubscribe();
        }

        if (networkNode != null) {
            networkNode.shutDown(() -> shutDownResultHandlers.forEach(Runnable::run));
        } else {
            shutDownResultHandlers.forEach(Runnable::run);
        }
    }

    /**
     * Startup sequence:
     * <p/>
     * Variant 1 (normal expected mode):
     * onTorNodeReady -> requestDataManager.firstDataRequestFromAnySeedNode()
     * RequestDataManager.Listener.onDataReceived && onHiddenServicePublished -> onNetworkReady()
     * <p/>
     * Variant 2 (no seed node available):
     * onTorNodeReady -> requestDataManager.firstDataRequestFromAnySeedNode
     * retry after 20-30 sec until we get at least one seed node connected
     * RequestDataManager.Listener.onDataReceived && onHiddenServicePublished -> onNetworkReady()
     */

    ///////////////////////////////////////////////////////////////////////////////////////////
    // SetupListener implementation
    ///////////////////////////////////////////////////////////////////////////////////////////
    @Override
    public void onTorNodeReady() {
        socks5ProxyProvider.setSocks5ProxyInternal(networkNode);

        requestDataManager.requestPreliminaryData();
        keepAliveManager.start();
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(SetupListener::onTorNodeReady);
        }
    }

    @Override
    public void onHiddenServicePublished() {
        checkArgument(networkNode.getNodeAddress() != null, "Address must be set when we have the hidden service ready");

        hiddenServicePublished.set(true);

        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(SetupListener::onHiddenServicePublished);
        }
    }

    @Override
    public void onSetupFailed(Throwable throwable) {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(e -> e.onSetupFailed(throwable));
        }
    }

    @Override
    public void onRequestCustomBridges() {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(SetupListener::onRequestCustomBridges);
        }
    }

    // Called from networkReadyBinding
    private void onNetworkReady() {
        networkReadySubscription.unsubscribe();

        Optional<NodeAddress> seedNodeOfPreliminaryDataRequest = requestDataManager.getNodeAddressOfPreliminaryDataRequest();
        checkArgument(seedNodeOfPreliminaryDataRequest.isPresent(),
                "seedNodeOfPreliminaryDataRequest must be present");

        requestDataManager.requestUpdateData();

        // If we start up first time we don't have any peers so we need to request from seed node.
        // As well it can be that the persisted peer list is outdated with dead peers.
        UserThread.runAfter(() -> {
            peerExchangeManager.requestReportedPeersFromSeedNodes(seedNodeOfPreliminaryDataRequest.get());
        }, 100, TimeUnit.MILLISECONDS);

        // If we have reported or persisted peers we try to connect to those
        UserThread.runAfter(peerExchangeManager::initialRequestPeersFromReportedOrPersistedPeers, 300, TimeUnit.MILLISECONDS);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // RequestDataManager.Listener implementation
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onPreliminaryDataReceived() {
        checkArgument(!preliminaryDataReceived.get(), "preliminaryDataReceived was already set before.");

        preliminaryDataReceived.set(true);
    }

    @Override
    public void onUpdatedDataReceived() {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(P2PServiceListener::onUpdatedDataReceived);
        }
    }

    @Override
    public void onNoSeedNodeAvailable() {
        applyIsBootstrapped(P2PServiceListener::onNoSeedNodeAvailable);
    }

    @Override
    public void onNoPeersAvailable() {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.forEach(P2PServiceListener::onNoPeersAvailable);
        }
    }

    @Override
    public void onDataReceived() {
        applyIsBootstrapped(P2PServiceListener::onDataReceived);

    }

    private void applyIsBootstrapped(Consumer<P2PServiceListener> listenerHandler) {
        if (!isBootstrapped) {
            isBootstrapped = true;

            p2PDataStorage.onBootstrapped();

            // We don't use a listener at mailboxMessageService as we require the correct
            // order of execution. The mailboxMessageService must be called before.
            mailboxMessageService.onBootstrapped();

            // Once we have applied the state in the P2P domain we notify our listeners
            synchronized (p2pServiceListeners) {
                p2pServiceListeners.forEach(listenerHandler);
            }

            mailboxMessageService.initAfterBootstrapped();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // ConnectionListener implementation
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onConnection(Connection connection) {
        numConnectedPeers.set(networkNode.getAllConnections().size());
        //TODO check if still needed and why
        UserThread.runAfter(() -> numConnectedPeers.set(networkNode.getAllConnections().size()), 3);
    }

    @Override
    public void onDisconnect(CloseConnectionReason closeConnectionReason, Connection connection) {
        numConnectedPeers.set(networkNode.getAllConnections().size());
        //TODO check if still needed and why
        UserThread.runAfter(() -> numConnectedPeers.set(networkNode.getAllConnections().size()), 3);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // MessageListener implementation
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    public void onMessage(NetworkEnvelope networkEnvelope, Connection connection) {
        if (networkEnvelope instanceof PrefixedSealedAndSignedMessage) {
            PrefixedSealedAndSignedMessage sealedMsg = (PrefixedSealedAndSignedMessage) networkEnvelope;
            try {
                DecryptedMessageWithPubKey decryptedMsg = encryptionService.decryptAndVerify(sealedMsg.getSealedAndSigned());
                connection.maybeHandleSupportedCapabilitiesMessage(decryptedMsg.getNetworkEnvelope());
                connection.getPeersNodeAddressOptional().ifPresentOrElse(nodeAddress -> {
                        synchronized (decryptedDirectMessageListeners) {
                            decryptedDirectMessageListeners.forEach(e -> e.onDirectMessage(decryptedMsg, nodeAddress));
                        }
                    }, () -> {
                        log.error("peersNodeAddress is expected to be available at onMessage for " +
                                "processing PrefixedSealedAndSignedMessage.");
                    });
            } catch (CryptoException e) {
                log.warn("Decryption of a direct message failed. This is not expected as the " +
                        "direct message was sent to our node.");
            } catch (ProtobufferException e) {
                log.error("ProtobufferException at decryptAndVerify: {}", e.toString());
                e.getStackTrace();
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // DirectMessages
    ///////////////////////////////////////////////////////////////////////////////////////////

    public void sendEncryptedDirectMessage(NodeAddress peerNodeAddress, PubKeyRing pubKeyRing, NetworkEnvelope message,
                                           SendDirectMessageListener sendDirectMessageListener) {
        sendEncryptedDirectMessage(peerNodeAddress, pubKeyRing, message, sendDirectMessageListener, null);
    }

    public void sendEncryptedDirectMessage(NodeAddress peerNodeAddress, PubKeyRing pubKeyRing, NetworkEnvelope message,
                                           SendDirectMessageListener sendDirectMessageListener, Integer timeoutSeconds) {
        checkNotNull(peerNodeAddress, "PeerAddress must not be null (sendEncryptedDirectMessage)");
        if (isBootstrapped()) {
            doSendEncryptedDirectMessage(peerNodeAddress, pubKeyRing, message, sendDirectMessageListener, timeoutSeconds);
        } else {
            throw new NetworkNotReadyException();
        }
    }

    private void doSendEncryptedDirectMessage(@NotNull NodeAddress peersNodeAddress,
                                              PubKeyRing pubKeyRing,
                                              NetworkEnvelope message,
                                              SendDirectMessageListener sendDirectMessageListener,
                                              Integer timeoutSeconds) {
        log.debug("Send encrypted direct message {} to peer {}",
                message.getClass().getSimpleName(), peersNodeAddress);

        checkNotNull(peersNodeAddress, "Peer node address must not be null at doSendEncryptedDirectMessage");

        checkNotNull(networkNode.getNodeAddress(), "My node address must not be null at doSendEncryptedDirectMessage");

        if (CapabilityUtils.capabilityRequiredAndCapabilityNotSupported(peersNodeAddress, message, peerManager)) {
            sendDirectMessageListener.onFault("We did not send the EncryptedMessage " +
                    "because the peer does not support the capability.");
            return;
        }

        try {
            // Prefix is not needed for direct messages but as old code is doing the verification we still need to
            // send it if peer has not updated.
            PrefixedSealedAndSignedMessage sealedMsg = new PrefixedSealedAndSignedMessage(
                    networkNode.getNodeAddress(),
                    encryptionService.encryptAndSign(pubKeyRing, message));

            SettableFuture<Connection> future = networkNode.sendMessage(peersNodeAddress, sealedMsg, timeoutSeconds);
            Futures.addCallback(future, new FutureCallback<>() {
                @Override
                public void onSuccess(@Nullable Connection connection) {
                    sendDirectMessageListener.onArrived();
                }

                @Override
                public void onFailure(@NotNull Throwable throwable) {
                    log.error(ExceptionUtils.getStackTrace(throwable));
                    sendDirectMessageListener.onFault(throwable.toString());
                }
            }, MoreExecutors.directExecutor());
        } catch (CryptoException e) {
            log.error("Error sending encrypted direct message, message={}, error={}\n", message.toString(), e.getMessage(), e);
            sendDirectMessageListener.onFault(e.toString());
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Data storage
    ///////////////////////////////////////////////////////////////////////////////////////////

    public boolean addPersistableNetworkPayload(PersistableNetworkPayload payload, boolean reBroadcast) {
        return p2PDataStorage.addPersistableNetworkPayload(payload, networkNode.getNodeAddress(), reBroadcast);
    }

    public boolean addProtectedStorageEntry(ProtectedStoragePayload protectedStoragePayload) {
        if (isBootstrapped()) {
            try {
                ProtectedStorageEntry protectedStorageEntry = p2PDataStorage.getProtectedStorageEntry(protectedStoragePayload, keyRing.getSignatureKeyPair());
                return p2PDataStorage.addProtectedStorageEntry(protectedStorageEntry, networkNode.getNodeAddress(), null);
            } catch (CryptoException e) {
                log.error("Signing at getDataWithSignedSeqNr failed. That should never happen.");
                return false;
            }
        } else {
            throw new NetworkNotReadyException();
        }
    }

    public boolean refreshTTL(ProtectedStoragePayload protectedStoragePayload) {
        if (isBootstrapped()) {
            try {
                RefreshOfferMessage refreshTTLMessage = p2PDataStorage.getRefreshTTLMessage(protectedStoragePayload, keyRing.getSignatureKeyPair());
                return p2PDataStorage.refreshTTL(refreshTTLMessage, networkNode.getNodeAddress());
            } catch (CryptoException e) {
                log.error("Signing at getDataWithSignedSeqNr failed. That should never happen.");
                return false;
            }
        } else {
            throw new NetworkNotReadyException();
        }
    }

    public boolean removeData(ProtectedStoragePayload protectedStoragePayload) {
        if (isBootstrapped()) {
            try {
                ProtectedStorageEntry protectedStorageEntry = p2PDataStorage.getProtectedStorageEntry(protectedStoragePayload, keyRing.getSignatureKeyPair());
                return p2PDataStorage.remove(protectedStorageEntry, networkNode.getNodeAddress());
            } catch (CryptoException e) {
                log.error("Signing at getDataWithSignedSeqNr failed. That should never happen.");
                return false;
            }
        } else {
            throw new NetworkNotReadyException();
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Listeners
    ///////////////////////////////////////////////////////////////////////////////////////////

    public void addDecryptedDirectMessageListener(DecryptedDirectMessageListener listener) {
        synchronized (decryptedDirectMessageListeners) {
            decryptedDirectMessageListeners.add(listener);
        }
    }

    public void removeDecryptedDirectMessageListener(DecryptedDirectMessageListener listener) {
        synchronized (decryptedDirectMessageListeners) {
            decryptedDirectMessageListeners.remove(listener);
        }
    }

    public void addP2PServiceListener(P2PServiceListener listener) {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.add(listener);
        }
    }

    public void removeP2PServiceListener(P2PServiceListener listener) {
        synchronized (p2pServiceListeners) {
            p2pServiceListeners.remove(listener);
        }
    }

    public void addHashSetChangedListener(HashMapChangedListener hashMapChangedListener) {
        p2PDataStorage.addHashMapChangedListener(hashMapChangedListener);
    }

    public void removeHashMapChangedListener(HashMapChangedListener hashMapChangedListener) {
        p2PDataStorage.removeHashMapChangedListener(hashMapChangedListener);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Getters
    ///////////////////////////////////////////////////////////////////////////////////////////

    public boolean isBootstrapped() {
        return isBootstrapped;
    }

    public NetworkNode getNetworkNode() {
        return networkNode;
    }

    @Nullable
    public NodeAddress getAddress() {
        return networkNode.getNodeAddress();
    }

    public ReadOnlyIntegerProperty getNumConnectedPeers() {
        return numConnectedPeers;
    }

    public Map<P2PDataStorage.ByteArray, ProtectedStorageEntry> getDataMap() {
        return p2PDataStorage.getMap();
    }

    @VisibleForTesting
    public P2PDataStorage getP2PDataStorage() {
        return p2PDataStorage;
    }

    @VisibleForTesting
    public PeerManager getPeerManager() {
        return peerManager;
    }

    @VisibleForTesting
    public KeyRing getKeyRing() {
        return keyRing;
    }

    // TODO: this is unreliable and unused, because peer sometimes reports no TRADE_STATISTICS_3 capability, causing valid trades to be unpublished
    public Optional<Capabilities> findPeersCapabilities(NodeAddress peer) {
        return networkNode.getConfirmedConnections().stream()
                .filter(e -> e.getPeersNodeAddressOptional().isPresent())
                .filter(e -> e.getPeersNodeAddressOptional().get().equals(peer))
                .map(Connection::getCapabilities)
                .findAny();
    }
}
