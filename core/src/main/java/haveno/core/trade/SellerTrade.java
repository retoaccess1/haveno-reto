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

import haveno.core.offer.Offer;
import haveno.core.trade.protocol.ProcessModel;
import haveno.core.xmr.wallet.XmrWalletService;
import haveno.network.p2p.NodeAddress;
import lombok.extern.slf4j.Slf4j;

import javax.annotation.Nullable;
import java.math.BigInteger;
import java.util.Date;

@Slf4j
public abstract class SellerTrade extends Trade {

    private static final long resendPaymentReceivedMessagesDurationMs = 2L * 30 * 24 * 60 * 60 * 1000; // ~2 months

    SellerTrade(Offer offer,
                BigInteger tradeAmount,
                long tradePrice,
                XmrWalletService xmrWalletService,
                ProcessModel processModel,
                String uid,
                @Nullable NodeAddress makerNodeAddress,
                @Nullable NodeAddress takerNodeAddress,
                @Nullable NodeAddress arbitratorNodeAddress,
                @Nullable String challenge) {
        super(offer,
                tradeAmount,
                tradePrice,
                xmrWalletService,
                processModel,
                uid,
                makerNodeAddress,
                takerNodeAddress,
                arbitratorNodeAddress,
                challenge);
    }

    @Override
    public BigInteger getPayoutAmountBeforeCost() {
        return getSellerSecurityDepositBeforeMiningFee();
    }

    @Override
    public boolean confirmPermitted() {
        return true;
    }

    public boolean isFinished() {
        return super.isFinished() && !needsToResendPaymentReceivedMessages();
    }

    public boolean needsToResendPaymentReceivedMessages() {
        return !isShutDownStarted() && getState().ordinal() >= Trade.State.SELLER_SENT_PAYMENT_RECEIVED_MSG.ordinal() && !getProcessModel().isPaymentReceivedMessagesReceived() && resendPaymentReceivedMessagesEnabled() && resendPaymentReceivedMessagesWithinDuration();
    }

    private boolean resendPaymentReceivedMessagesEnabled() {
        return getOffer().getOfferPayload().getProtocolVersion() >= 2;
    }

    public boolean resendPaymentReceivedMessagesWithinDuration() {
        Date startDate = getMaxTradePeriodDate(); // TODO: preferably use the date when the payment receipt was confirmed
        return new Date().getTime() <= (startDate.getTime() + resendPaymentReceivedMessagesDurationMs);
    }
}

