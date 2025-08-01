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

package haveno.core.trade;

import static com.google.common.base.Preconditions.checkNotNull;
import com.google.inject.Inject;
import com.google.inject.Singleton;
import haveno.common.crypto.KeyRing;
import haveno.common.util.Tuple2;
import static haveno.core.locale.CurrencyUtil.getCurrencyPair;
import haveno.core.locale.Res;
import haveno.core.offer.Offer;
import static haveno.core.util.FormattingUtils.formatDurationAsWords;
import haveno.core.xmr.wallet.BtcWalletService;
import static java.lang.String.format;
import java.util.Date;
import java.util.Objects;
import javax.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;

/**
 * This class contains trade utility methods.
 */
@Slf4j
@Singleton
public class TradeUtil {

    private final BtcWalletService btcWalletService;
    private final KeyRing keyRing;

    @Inject
    public TradeUtil(BtcWalletService btcWalletService, KeyRing keyRing) {
        this.btcWalletService = btcWalletService;
        this.keyRing = keyRing;
    }

    /**
     * Returns <MULTI_SIG, TRADE_PAYOUT> if and only if both are AVAILABLE,
     * otherwise null.
     * @param trade the trade being queried for MULTI_SIG, TRADE_PAYOUT addresses
     * @return Tuple2 tuple containing MULTI_SIG, TRADE_PAYOUT addresses for trade
     */
    public Tuple2<String, String> getAvailableAddresses(Trade trade) {
        var addresses = getTradeAddresses(trade);
        if (addresses == null)
            return null;

        if (btcWalletService.getAvailableAddressEntries().stream()
                .noneMatch(e -> Objects.equals(e.getAddressString(), addresses.first)))
            return null;

        if (btcWalletService.getAvailableAddressEntries().stream()
                .noneMatch(e -> Objects.equals(e.getAddressString(), addresses.second)))
            return null;

        return new Tuple2<>(addresses.first, addresses.second);
    }

    /**
     * Returns <MULTI_SIG, TRADE_PAYOUT> addresses as strings if they're known by the
     * wallet.
     * @param trade the trade being queried for MULTI_SIG, TRADE_PAYOUT addresses
     * @return Tuple2 tuple containing MULTI_SIG, TRADE_PAYOUT addresses for trade
     */
    public Tuple2<String, String> getTradeAddresses(Trade trade) {
        throw new RuntimeException("TradeUtil.getTradeAddresses() not implemented for XMR");
//        var contract = trade.getContract();
//        if (contract == null)
//            return null;
//
//        // Get multisig address
//        var isMyRoleBuyer = contract.isMyRoleBuyer(keyRing.getPubKeyRing());
//        var multiSigPubKey = isMyRoleBuyer
//                ? contract.getBuyerMultiSigPubKey()
//                : contract.getSellerMultiSigPubKey();
//        if (multiSigPubKey == null)
//            return null;
//
//        var multiSigPubKeyString = Utilities.bytesAsHexString(multiSigPubKey);
//        var multiSigAddress = btcWalletService.getAddressEntryListAsImmutableList().stream()
//                .filter(e -> e.getKeyPair().getPublicKeyAsHex().equals(multiSigPubKeyString))
//                .findAny()
//                .orElse(null);
//        if (multiSigAddress == null)
//            return null;
//
//        // Get payout address
//        var payoutAddress = isMyRoleBuyer
//                ? contract.getBuyerPayoutAddressString()
//                : contract.getSellerPayoutAddressString();
//        var payoutAddressEntry = btcWalletService.getAddressEntryListAsImmutableList().stream()
//                .filter(e -> Objects.equals(e.getAddressString(), payoutAddress))
//                .findAny()
//                .orElse(null);
//        if (payoutAddressEntry == null)
//            return null;
//
//        return new Tuple2<>(multiSigAddress.getAddressString(), payoutAddress);
    }

    public long getRemainingTradeDuration(Trade trade) {
        return trade.getMaxTradePeriodDate() != null
                ? trade.getMaxTradePeriodDate().getTime() - new Date().getTime()
                : getMaxTradePeriod(trade);
    }

    public long getMaxTradePeriod(Trade trade) {
        return trade.getOffer() != null
                ? trade.getOffer().getPaymentMethod().getMaxTradePeriod()
                : 0;
    }

    public double getRemainingTradeDurationAsPercentage(Trade trade) {
        long maxPeriod = getMaxTradePeriod(trade);
        long remaining = getRemainingTradeDuration(trade);
        if (maxPeriod != 0) {
            return 1 - (double) remaining / (double) maxPeriod;
        } else
            return 0;
    }

    public String getRemainingTradeDurationAsWords(Trade trade) {
        return formatDurationAsWords(Math.max(0, getRemainingTradeDuration(trade)));
    }

    @Nullable
    public Date getHalfTradePeriodDate(Trade trade) {
        return trade != null ? trade.getHalfTradePeriodDate() : null;
    }

    public Date getDateForOpenDispute(Trade trade) {
        return new Date(new Date().getTime() + getRemainingTradeDuration(trade));
    }

    public String getMarketDescription(Trade trade) {
        if (trade == null)
            return "";

        checkNotNull(trade.getOffer());
        checkNotNull(trade.getOffer().getCounterCurrencyCode());
        return getCurrencyPair(trade.getOffer().getCounterCurrencyCode());
    }

    public String getPaymentMethodNameWithCountryCode(Trade trade) {
        if (trade == null)
            return "";

        Offer offer = trade.getOffer();
        checkNotNull(offer);
        checkNotNull(offer.getPaymentMethod());
        return offer.getPaymentMethodNameWithCountryCode();
    }

    /**
     * Returns a string describing a trader's role for a given trade.
     * @param trade Trade
     * @return String describing a trader's role for a given trade
     */
    public static String getRole(Trade trade) {
        Offer offer = trade.getOffer();
        if (offer == null)
            throw new IllegalStateException(format("could not get role because no offer was found for trade '%s'",
                    trade.getShortId()));
        return (trade.isArbitrator() ? "Arbitrator for " : "") + // TODO: use Res.get()
                getRole(trade.getBuyer() == trade.getMaker(),
                        trade.isArbitrator() ? true : trade.isMaker(), // arbitrator role in context of maker
                        offer.getCounterCurrencyCode());
    }

    /**
     * Returns a string describing a trader's role.
     *
     * @param isBuyerMakerAndSellerTaker boolean
     * @param isMaker boolean
     * @param currencyCode String
     * @return String describing a trader's role
     */
    private static String getRole(boolean isBuyerMakerAndSellerTaker, boolean isMaker, String currencyCode) {
        String baseCurrencyCode = Res.getBaseCurrencyCode();
        if (isBuyerMakerAndSellerTaker)
            return isMaker
                    ? Res.get("formatter.asMaker", baseCurrencyCode, Res.get("shared.buyer"))
                    : Res.get("formatter.asTaker", baseCurrencyCode, Res.get("shared.seller"));
        else
            return isMaker
                    ? Res.get("formatter.asMaker", baseCurrencyCode, Res.get("shared.seller"))
                    : Res.get("formatter.asTaker", baseCurrencyCode, Res.get("shared.buyer"));
    }
}
