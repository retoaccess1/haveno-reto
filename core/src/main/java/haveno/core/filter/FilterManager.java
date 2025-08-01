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

package haveno.core.filter;

import static com.google.common.base.Preconditions.checkNotNull;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import haveno.common.app.DevEnv;
import haveno.common.app.Version;
import haveno.common.config.Config;
import haveno.common.config.ConfigFileEditor;
import haveno.common.crypto.KeyRing;
import haveno.core.locale.Res;
import haveno.core.payment.payload.PaymentAccountPayload;
import haveno.core.payment.payload.PaymentMethod;
import haveno.core.provider.ProvidersRepository;
import haveno.core.user.Preferences;
import haveno.core.user.User;
import haveno.core.xmr.nodes.XmrNodes;
import haveno.network.p2p.NodeAddress;
import haveno.network.p2p.P2PService;
import haveno.network.p2p.P2PServiceListener;
import haveno.network.p2p.network.BanFilter;
import haveno.network.p2p.storage.HashMapChangedListener;
import haveno.network.p2p.storage.payload.ProtectedStorageEntry;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleObjectProperty;
import javax.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import static org.bitcoinj.core.Utils.HEX;
import org.bouncycastle.util.encoders.Base64;

/**
 * We only support one active filter, if we receive multiple we use the one with the more recent creationDate.
 */
@Slf4j
public class FilterManager {
    private static final String BANNED_PRICE_RELAY_NODES = "bannedPriceRelayNodes";
    private static final String BANNED_SEED_NODES = "bannedSeedNodes";
    private static final String BANNED_XMR_NODES = "bannedXmrNodes";

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Listener
    ///////////////////////////////////////////////////////////////////////////////////////////

    public interface Listener {
        void onFilterAdded(Filter filter);
    }

    private final P2PService p2PService;
    private final KeyRing keyRing;
    private final User user;
    private final Preferences preferences;
    private final ConfigFileEditor configFileEditor;
    private final ProvidersRepository providersRepository;
    private final boolean ignoreDevMsg;
    private final boolean useDevPrivilegeKeys;
    private final ObjectProperty<Filter> filterProperty = new SimpleObjectProperty<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private ECKey filterSigningKey;
    private final Set<Filter> invalidFilters = new HashSet<>();
    private Consumer<String> filterWarningHandler;


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Inject
    public FilterManager(P2PService p2PService,
                         KeyRing keyRing,
                         User user,
                         Preferences preferences,
                         Config config,
                         ProvidersRepository providersRepository,
                         BanFilter banFilter,
                         @Named(Config.IGNORE_DEV_MSG) boolean ignoreDevMsg,
                         @Named(Config.USE_DEV_PRIVILEGE_KEYS) boolean useDevPrivilegeKeys) {
        this.p2PService = p2PService;
        this.keyRing = keyRing;
        this.user = user;
        this.preferences = preferences;
        this.configFileEditor = new ConfigFileEditor(config.configFile);
        this.providersRepository = providersRepository;
        this.ignoreDevMsg = ignoreDevMsg;
        this.useDevPrivilegeKeys = useDevPrivilegeKeys;

        banFilter.setBannedNodePredicate(this::isNodeAddressBannedFromNetwork);
    }

    protected List<String> getPubKeyList() {
        switch (Config.baseCurrencyNetwork()) {
        case XMR_LOCAL:
            if (useDevPrivilegeKeys) return Collections.singletonList(DevEnv.DEV_PRIVILEGE_PUB_KEY);
            return List.of(
                    "027a381b5333a56e1cc3d90d3a7d07f26509adf7029ed06fc997c656621f8da1ee",
                    "024baabdba90e7cc0dc4626ef73ea9d722ea7085d1104491da8c76f28187513492",
                    "026eeec3c119dd6d537249d74e5752a642dd2c3cc5b6a9b44588eb58344f29b519");
        case XMR_STAGENET:
            return List.of(
                    "03aa23e062afa0dda465f46986f8aa8d0374ad3e3f256141b05681dcb1e39c3859",
                    "02d3beb1293ca2ca14e6d42ca8bd18089a62aac62fd6bb23923ee6ead46ac60fba",
                    "0374dd70f3fa6e47ec5ab97932e1cec6233e98e6ae3129036b17118650c44fd3de");
        case XMR_MAINNET:
            return List.of(
                    "02d8ac0fbe4e25f4a1d68b95936f25fc2e1b218e161cb5ed6661c7ab4c85f1fd4f",
                    "02e9dc14edddde19cc9f829a0739d0ab0c7310154ad94a15d477b51d85991b5a8a",
                    "03c8efdf81287ce8b3212241e6aa7cdf094ecbed2d2f119730a3e4d596a764106a");
        default:
            throw new RuntimeException("Unhandled base currency network: " + Config.baseCurrencyNetwork());
        }
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // API
    ///////////////////////////////////////////////////////////////////////////////////////////

    public void onAllServicesInitialized() {
        if (ignoreDevMsg) {
            return;
        }

        p2PService.getP2PDataStorage().getMap().values().stream()
                .map(ProtectedStorageEntry::getProtectedStoragePayload)
                .filter(protectedStoragePayload -> protectedStoragePayload instanceof Filter)
                .map(protectedStoragePayload -> (Filter) protectedStoragePayload)
                .forEach(this::onFilterAddedFromNetwork);

        // On mainNet we expect to have received a filter object, if not show a popup to the user to inform the
        // Haveno devs.
        if (Config.baseCurrencyNetwork().isMainnet() && getFilter() == null && filterWarningHandler != null) {
            filterWarningHandler.accept(Res.get("popup.warning.noFilter"));
        }

        p2PService.addHashSetChangedListener(new HashMapChangedListener() {
            @Override
            public void onAdded(Collection<ProtectedStorageEntry> protectedStorageEntries) {
                protectedStorageEntries.stream()
                        .filter(protectedStorageEntry -> protectedStorageEntry.getProtectedStoragePayload() instanceof Filter)
                        .forEach(protectedStorageEntry -> {
                            Filter filter = (Filter) protectedStorageEntry.getProtectedStoragePayload();
                            onFilterAddedFromNetwork(filter);
                        });
            }

            @Override
            public void onRemoved(Collection<ProtectedStorageEntry> protectedStorageEntries) {
                protectedStorageEntries.stream()
                        .filter(protectedStorageEntry -> protectedStorageEntry.getProtectedStoragePayload() instanceof Filter)
                        .forEach(protectedStorageEntry -> {
                            Filter filter = (Filter) protectedStorageEntry.getProtectedStoragePayload();
                            onFilterRemovedFromNetwork(filter);
                        });
            }
        });

        p2PService.addP2PServiceListener(new P2PServiceListener() {
            @Override
            public void onDataReceived() {
            }

            @Override
            public void onNoSeedNodeAvailable() {
            }

            @Override
            public void onNoPeersAvailable() {
            }

            @Override
            public void onUpdatedDataReceived() {
                // We should have received all data at that point and if the filters were not set we
                // clean up the persisted banned nodes in the options file as it might be that we missed the filter
                // remove message if we have not been online.
                if (filterProperty.get() == null) {
                    clearBannedNodes();
                }
            }

            @Override
            public void onTorNodeReady() {
            }

            @Override
            public void onHiddenServicePublished() {
            }

            @Override
            public void onSetupFailed(Throwable throwable) {
            }

            @Override
            public void onRequestCustomBridges() {
            }
        });
    }

    public void setFilterWarningHandler(Consumer<String> filterWarningHandler) {
        this.filterWarningHandler = filterWarningHandler;

        addListener(filter -> {
            if (filter != null && filterWarningHandler != null) {
                if (filter.getSeedNodes() != null && !filter.getSeedNodes().isEmpty()) {
                    log.info("One of the seed nodes got banned. {}", filter.getSeedNodes());
                    // Let's keep that more silent. Might be used in case a node is unstable and we don't want to confuse users.
                    // filterWarningHandler.accept(Res.get("popup.warning.nodeBanned", Res.get("popup.warning.seed")));
                }

                if (filter.getPriceRelayNodes() != null && !filter.getPriceRelayNodes().isEmpty()) {
                    log.info("One of the price relay nodes got banned. {}", filter.getPriceRelayNodes());
                    // Let's keep that more silent. Might be used in case a node is unstable and we don't want to confuse users.
                    // filterWarningHandler.accept(Res.get("popup.warning.nodeBanned", Res.get("popup.warning.priceRelay")));
                }

                if (requireUpdateToNewVersionForTrading()) {
                    filterWarningHandler.accept(Res.get("popup.warning.mandatoryUpdate.trading"));
                }
            }
        });
    }

    public boolean isPrivilegedDevPubKeyBanned(String pubKeyAsHex) {
        Filter filter = getFilter();
        if (filter == null) {
            return false;
        }

        return filter.getBannedPrivilegedDevPubKeys().contains(pubKeyAsHex);
    }

    public boolean canAddDevFilter(String privKeyString) {
        if (privKeyString == null || privKeyString.isEmpty()) {
            return false;
        }
        if (!isValidDevPrivilegeKey(privKeyString)) {
            log.warn("Key in invalid");
            return false;
        }

        ECKey ecKeyFromPrivate = toECKey(privKeyString);
        String pubKeyAsHex = getPubKeyAsHex(ecKeyFromPrivate);
        if (isPrivilegedDevPubKeyBanned(pubKeyAsHex)) {
            log.warn("Pub key is banned.");
            return false;
        }
        return true;
    }

    public String getSignerPubKeyAsHex(String privKeyString) {
        ECKey ecKey = toECKey(privKeyString);
        return getPubKeyAsHex(ecKey);
    }

    public void addDevFilter(Filter filterWithoutSig, String privKeyString) {
        setFilterSigningKey(privKeyString);
        String signatureAsBase64 = getSignature(filterWithoutSig);
        Filter filterWithSig = Filter.cloneWithSig(filterWithoutSig, signatureAsBase64);
        user.setDevelopersFilter(filterWithSig);

        p2PService.addProtectedStorageEntry(filterWithSig);

        // Cleanup potential old filters created in the past with same priv key
        invalidFilters.forEach(filter -> {
            removeInvalidFilters(filter, privKeyString);
        });
    }

    public void addToInvalidFilters(Filter filter) {
        invalidFilters.add(filter);
    }

    public void removeInvalidFilters(Filter filter, String privKeyString) {
        // We can only remove the filter if it's our own filter
        if (Arrays.equals(filter.getOwnerPubKey().getEncoded(), keyRing.getSignatureKeyPair().getPublic().getEncoded())) {
            log.info("Remove invalid filter {}", filter);
            setFilterSigningKey(privKeyString);
            String signatureAsBase64 = getSignature(Filter.cloneWithoutSig(filter));
            Filter filterWithSig = Filter.cloneWithSig(filter, signatureAsBase64);
            boolean result = p2PService.removeData(filterWithSig);
            if (!result) {
                log.warn("Could not remove filter {}", filter);
            }
        } else {
            log.info("The invalid filter is not our own, so we cannot remove it from the network");
        }
    }

    public boolean canRemoveDevFilter(String privKeyString) {
        if (privKeyString == null || privKeyString.isEmpty()) {
            return false;
        }

        Filter developersFilter = getDevFilter();
        if (developersFilter == null) {
            log.warn("There is no persisted dev filter to be removed.");
            return false;
        }

        if (!isValidDevPrivilegeKey(privKeyString)) {
            log.warn("Key in invalid.");
            return false;
        }

        ECKey ecKeyFromPrivate = toECKey(privKeyString);
        String pubKeyAsHex = getPubKeyAsHex(ecKeyFromPrivate);
        if (!developersFilter.getSignerPubKeyAsHex().equals(pubKeyAsHex)) {
            log.warn("pubKeyAsHex derived from private key does not match filterSignerPubKey. " +
                            "filterSignerPubKey={}, pubKeyAsHex derived from private key={}",
                    developersFilter.getSignerPubKeyAsHex(), pubKeyAsHex);
            return false;
        }

        if (isPrivilegedDevPubKeyBanned(pubKeyAsHex)) {
            log.warn("Pub key is banned.");
            return false;
        }

        return true;
    }

    public void removeDevFilter(String privKeyString) {
        setFilterSigningKey(privKeyString);
        Filter filterWithSig = user.getDevelopersFilter();
        if (filterWithSig == null) {
            // Should not happen as UI button is deactivated in that case
            return;
        }

        if (p2PService.removeData(filterWithSig)) {
            user.setDevelopersFilter(null);
        } else {
            log.warn("Removing dev filter from network failed");
        }
    }

    public void addListener(Listener listener) {
        listeners.add(listener);
    }

    public ObjectProperty<Filter> filterProperty() {
        return filterProperty;
    }

    @Nullable
    public Filter getFilter() {
        return filterProperty.get();
    }

    @Nullable
    public Filter getDevFilter() {
        return user.getDevelopersFilter();
    }

    public PublicKey getOwnerPubKey() {
        return keyRing.getSignatureKeyPair().getPublic();
    }

    public boolean isCurrencyBanned(String currencyCode) {
        return getFilter() != null &&
                getFilter().getBannedCurrencies() != null &&
                getFilter().getBannedCurrencies().stream()
                        .anyMatch(e -> e.equals(currencyCode));
    }

    public boolean isPaymentMethodBanned(PaymentMethod paymentMethod) {
        return getFilter() != null &&
                getFilter().getBannedPaymentMethods() != null &&
                getFilter().getBannedPaymentMethods().stream()
                        .anyMatch(e -> e.equals(paymentMethod.getId()));
    }

    public boolean isOfferIdBanned(String offerId) {
        return getFilter() != null &&
                getFilter().getBannedOfferIds().stream()
                        .anyMatch(e -> e.equals(offerId));
    }

    public boolean isNodeAddressBanned(NodeAddress nodeAddress) {
        return getFilter() != null &&
                getFilter().getNodeAddressesBannedFromTrading().stream()
                        .anyMatch(e -> e.equals(nodeAddress.getFullAddress()));
    }

    public boolean isNodeAddressBannedFromNetwork(NodeAddress nodeAddress) {
        return getFilter() != null &&
                getFilter().getNodeAddressesBannedFromNetwork().stream()
                        .anyMatch(e -> e.equals(nodeAddress.getFullAddress()));
    }

    public boolean isAutoConfExplorerBanned(String address) {
        return getFilter() != null &&
                getFilter().getBannedAutoConfExplorers().stream()
                        .anyMatch(e -> e.equals(address));
    }

    public String getDisableTradeBelowVersion() {
        return getFilter() == null || getFilter().getDisableTradeBelowVersion() == null || getFilter().getDisableTradeBelowVersion().isEmpty() ? null : getFilter().getDisableTradeBelowVersion();
    }

    public boolean requireUpdateToNewVersionForTrading() {
        if (getFilter() == null) {
            return false;
        }

        boolean requireUpdateToNewVersion = false;
        String getDisableTradeBelowVersion = getFilter().getDisableTradeBelowVersion();
        if (getDisableTradeBelowVersion != null && !getDisableTradeBelowVersion.isEmpty()) {
            requireUpdateToNewVersion = Version.isNewVersion(getDisableTradeBelowVersion);
        }

        return requireUpdateToNewVersion;
    }

    public boolean arePeersPaymentAccountDataBanned(PaymentAccountPayload paymentAccountPayload) {
        return getFilter() != null &&
                getFilter().getBannedPaymentAccounts().stream()
                        .filter(paymentAccountFilter -> paymentAccountFilter.getPaymentMethodId().equals(
                                paymentAccountPayload.getPaymentMethodId()))
                        .anyMatch(paymentAccountFilter -> {
                            try {
                                Method method = paymentAccountPayload.getClass().getMethod(paymentAccountFilter.getGetMethodName());
                                // We invoke getter methods (no args), e.g. getHolderName
                                String valueFromInvoke = (String) method.invoke(paymentAccountPayload);
                                return valueFromInvoke.equalsIgnoreCase(paymentAccountFilter.getValue());
                            } catch (Throwable e) {
                                log.error(e.getMessage());
                                return false;
                            }
                        });
    }

    public boolean isWitnessSignerPubKeyBanned(String witnessSignerPubKeyAsHex) {
        return getFilter() != null &&
                getFilter().getBannedAccountWitnessSignerPubKeys() != null &&
                getFilter().getBannedAccountWitnessSignerPubKeys().stream()
                        .anyMatch(e -> e.equals(witnessSignerPubKeyAsHex));
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Private
    ///////////////////////////////////////////////////////////////////////////////////////////

    private void onFilterAddedFromNetwork(Filter newFilter) {
        Filter currentFilter = getFilter();

        if (!isFilterPublicKeyInList(newFilter)) {
            if (newFilter.getSignerPubKeyAsHex() != null && !newFilter.getSignerPubKeyAsHex().isEmpty()) {
                log.warn("isFilterPublicKeyInList failed. Filter.getSignerPubKeyAsHex={}", newFilter.getSignerPubKeyAsHex());
            } else {
                log.info("isFilterPublicKeyInList failed. Filter.getSignerPubKeyAsHex not set (expected case for pre v1.3.9 filter)");
            }
            return;
        }
        if (!isSignatureValid(newFilter)) {
            log.warn("verifySignature failed. Filter={}", newFilter);
            return;
        }

        if (currentFilter != null) {
            if (currentFilter.getCreationDate() > newFilter.getCreationDate()) {
                log.info("We received a new filter from the network but the creation date is older than the " +
                        "filter we have already. We ignore the new filter.");

                addToInvalidFilters(newFilter);
                return;
            } else {
                log.info("We received a new filter from the network and the creation date is newer than the " +
                        "filter we have already. We ignore the old filter.");
                addToInvalidFilters(currentFilter);
            }

            if (isPrivilegedDevPubKeyBanned(newFilter.getSignerPubKeyAsHex())) {
                log.warn("Pub key of filter is banned. currentFilter={}, newFilter={}", currentFilter, newFilter);
                return;
            }
        }

        // Our new filter is newer so we apply it.
        // We do not require strict guarantees here (e.g. clocks not synced) as only trusted developers have the key
        // for deploying filters and this is only in place to avoid unintended situations of multiple filters
        // from multiple devs or if same dev publishes new filter from different app without the persisted devFilter.
        filterProperty.set(newFilter);

        // Seed nodes are requested at startup before we get the filter so we only apply the banned
        // nodes at the next startup and don't update the list in the P2P network domain.
        // We persist it to the property file which is read before any other initialisation.
        saveBannedNodes(BANNED_SEED_NODES, newFilter.getSeedNodes());
        saveBannedNodes(BANNED_XMR_NODES, newFilter.getXmrNodes());

        // Banned price relay nodes we can apply at runtime
        List<String> priceRelayNodes = newFilter.getPriceRelayNodes();
        saveBannedNodes(BANNED_PRICE_RELAY_NODES, priceRelayNodes);

        //TODO should be moved to client with listening on onFilterAdded
        providersRepository.applyBannedNodes(priceRelayNodes);

        //TODO should be moved to client with listening on onFilterAdded
        if (newFilter.isPreventPublicXmrNetwork() &&
                preferences.getMoneroNodesOptionOrdinal() == XmrNodes.MoneroNodesOption.PUBLIC.ordinal()) {
            preferences.setMoneroNodesOptionOrdinal(XmrNodes.MoneroNodesOption.PROVIDED.ordinal());
        }

        listeners.forEach(e -> e.onFilterAdded(newFilter));
    }

    private void onFilterRemovedFromNetwork(Filter filter) {
        if (!isFilterPublicKeyInList(filter)) {
            log.warn("isFilterPublicKeyInList failed. Filter={}", filter);
            return;
        }
        if (!isSignatureValid(filter)) {
            log.warn("verifySignature failed. Filter={}", filter);
            return;
        }

        // We don't check for banned filter as we want to remove a banned filter anyway.

        if (filterProperty.get() != null && !filterProperty.get().equals(filter)) {
            return;
        }

        clearBannedNodes();

        if (filter.equals(user.getDevelopersFilter())) {
            user.setDevelopersFilter(null);
        }
        filterProperty.set(null);
    }

    // Clears options files from banned nodes
    private void clearBannedNodes() {
        saveBannedNodes(BANNED_XMR_NODES, null);
        saveBannedNodes(BANNED_SEED_NODES, null);
        saveBannedNodes(BANNED_PRICE_RELAY_NODES, null);

        if (providersRepository.getBannedNodes() != null) {
            providersRepository.applyBannedNodes(null);
        }
    }

    private void saveBannedNodes(String optionName, List<String> bannedNodes) {
        if (bannedNodes != null)
            configFileEditor.setOption(optionName, String.join(",", bannedNodes));
        else
            configFileEditor.clearOption(optionName);
    }

    private boolean isValidDevPrivilegeKey(String privKeyString) {
        try {
            ECKey filterSigningKey = toECKey(privKeyString);
            String pubKeyAsHex = getPubKeyAsHex(filterSigningKey);
            return isPublicKeyInList(pubKeyAsHex);
        } catch (Throwable t) {
            return false;
        }
    }

    private void setFilterSigningKey(String privKeyString) {
        this.filterSigningKey = toECKey(privKeyString);
    }

    private String getSignature(Filter filterWithoutSig) {
        Sha256Hash hash = getSha256Hash(filterWithoutSig);
        ECKey.ECDSASignature ecdsaSignature = filterSigningKey.sign(hash);
        byte[] encodeToDER = ecdsaSignature.encodeToDER();
        return new String(Base64.encode(encodeToDER), StandardCharsets.UTF_8);
    }

    private boolean isFilterPublicKeyInList(Filter filter) {
        String signerPubKeyAsHex = filter.getSignerPubKeyAsHex();
        if (!isPublicKeyInList(signerPubKeyAsHex)) {
            log.info("Invalid filter (expected case for pre v1.3.9 filter as we still keep that in the network " +
                            "but the new version does not recognize it as valid filter): " +
                            "signerPubKeyAsHex from filter is not part of our pub key list. " +
                            "signerPubKeyAsHex={}, publicKeys={}, filterCreationDate={}",
                    signerPubKeyAsHex, getPubKeyList(), new Date(filter.getCreationDate()));
            return false;
        }
        return true;
    }

    private boolean isPublicKeyInList(String pubKeyAsHex) {
        boolean isPublicKeyInList = getPubKeyList().contains(pubKeyAsHex);
        if (!isPublicKeyInList) {
            log.info("pubKeyAsHex is not part of our pub key list (expected case for pre v1.3.9 filter). pubKeyAsHex={}, publicKeys={}", pubKeyAsHex, getPubKeyList());
        }
        return isPublicKeyInList;
    }

    private boolean isSignatureValid(Filter filter) {
        try {
            Filter filterForSigVerification = Filter.cloneWithoutSig(filter);
            Sha256Hash hash = getSha256Hash(filterForSigVerification);

            checkNotNull(filter.getSignatureAsBase64(), "filter.getSignatureAsBase64() must not be null");
            byte[] sigData = Base64.decode(filter.getSignatureAsBase64());
            ECKey.ECDSASignature ecdsaSignature = ECKey.ECDSASignature.decodeFromDER(sigData);

            String signerPubKeyAsHex = filter.getSignerPubKeyAsHex();
            byte[] decode = HEX.decode(signerPubKeyAsHex);
            ECKey ecPubKey = ECKey.fromPublicOnly(decode);
            return ecPubKey.verify(hash, ecdsaSignature);
        } catch (Throwable e) {
            log.warn("verifySignature failed. filter={}", filter);
            return false;
        }
    }

    private ECKey toECKey(String privKeyString) {
        return ECKey.fromPrivate(new BigInteger(1, HEX.decode(privKeyString)));
    }

    private Sha256Hash getSha256Hash(Filter filter) {
        byte[] filterData = filter.toProtoMessage().toByteArray();
        return Sha256Hash.of(filterData);
    }

    private String getPubKeyAsHex(ECKey ecKey) {
        return HEX.encode(ecKey.getPubKey());
    }
}
