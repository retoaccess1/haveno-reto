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

package haveno.core.util.coin;

import com.google.common.annotations.VisibleForTesting;
import haveno.common.util.MathUtils;
import haveno.core.locale.CurrencyUtil;
import haveno.core.monetary.Price;
import haveno.core.monetary.Volume;
import haveno.core.payment.payload.PaymentMethod;
import haveno.core.trade.HavenoUtils;
import haveno.core.xmr.wallet.Restrictions;
import org.bitcoinj.core.Coin;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.text.DecimalFormat;

import static com.google.common.base.Preconditions.checkArgument;
import static haveno.core.util.VolumeUtil.getAdjustedVolumeUnit;

public class CoinUtil {


    public static Coin minCoin(Coin a, Coin b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    public static Coin maxCoin(Coin a, Coin b) {
        return a.compareTo(b) >= 0 ? a : b;
    }

    /**
     * @param value Xmr amount to be converted to percent value. E.g. 0.01 XMR is 1% (of 1 XMR)
     * @return The percentage value as double (e.g. 1% is 0.01)
     */
    public static double getAsPercentPerXmr(BigInteger value) {
        return getAsPercentPerXmr(value, HavenoUtils.xmrToAtomicUnits(1.0));
    }

    /**
     * @param part Xmr amount to be converted to percent value, based on total value passed.
     *              E.g. 0.1 XMR is 25% (of 0.4 XMR)
     * @param total Total Xmr amount the percentage part is calculated from
     *
     * @return The percentage value as double (e.g. 1% is 0.01)
     */
    public static double getAsPercentPerXmr(BigInteger part, BigInteger total) {
        return MathUtils.roundDouble(HavenoUtils.divide(part == null ? BigInteger.ZERO : part, total == null ? BigInteger.valueOf(1) : total), 4);
    }

    /**
     * @param percent       The percentage value as double (e.g. 1% is 0.01)
     * @param amount        The amount as atomic units for the percentage calculation
     * @return The percentage as atomic units (e.g. 1% of 1 XMR is 0.01 XMR)
     */
    public static BigInteger getPercentOfAmount(double percent, BigInteger amount) {
        if (amount == null) amount = BigInteger.ZERO;
        return BigDecimal.valueOf(percent).multiply(new BigDecimal(amount)).setScale(8, RoundingMode.DOWN).toBigInteger();
    }

    public static BigInteger getRoundedAmount(BigInteger amount, Price price, BigInteger minAmount, BigInteger maxAmount, String currencyCode, String paymentMethodId) {
        if (price != null) {
            if (PaymentMethod.isRoundedForAtmCash(paymentMethodId)) {
                return getRoundedAtmCashAmount(amount, price, minAmount, maxAmount);
            } else if (CurrencyUtil.isVolumeRoundedToNearestUnit(currencyCode)) {
                return getRoundedAmountUnit(amount, price, minAmount, maxAmount);
            }
        }
        return getRoundedAmount4Decimals(amount);
    }

    public static BigInteger getRoundedAtmCashAmount(BigInteger amount, Price price, BigInteger minAmount, BigInteger maxAmount) {
        return getAdjustedAmount(amount, price, minAmount, maxAmount, 10);
    }

    /**
     * Calculate the possibly adjusted amount for {@code amount}, taking into account the
     * {@code price} and {@code maxTradeLimit} and {@code factor}.
     *
     * @param amount            Monero amount which is a candidate for getting rounded.
     * @param price             Price used in relation to that amount.
     * @param minAmount         The minimum amount.
     * @param maxAmount         The maximum amount.
     * @return The adjusted amount
     */
    public static BigInteger getRoundedAmountUnit(BigInteger amount, Price price, BigInteger minAmount, BigInteger maxAmount) {
        return getAdjustedAmount(amount, price, minAmount, maxAmount, 1);
    }
    
    public static BigInteger getRoundedAmount4Decimals(BigInteger amount) {
        DecimalFormat decimalFormat = new DecimalFormat("#.####", HavenoUtils.DECIMAL_FORMAT_SYMBOLS);
        double roundedXmrAmount = Double.parseDouble(decimalFormat.format(HavenoUtils.atomicUnitsToXmr(amount)));
        return HavenoUtils.xmrToAtomicUnits(roundedXmrAmount);
    }

    /**
     * Calculate the possibly adjusted amount for {@code amount}, taking into account the
     * {@code price} and {@code maxTradeLimit} and {@code factor}.
     *
     * @param amount            amount which is a candidate for getting rounded.
     * @param price             Price used in relation to that amount.
     * @param minAmount         The minimum amount.
     * @param maxAmount         The maximum amount.
     * @param factor            The factor used for rounding. E.g. 1 means rounded to units of
     *                          1 EUR, 10 means rounded to 10 EUR, etc.
     * @return The adjusted amount
     */
    @VisibleForTesting
    static BigInteger getAdjustedAmount(BigInteger amount, Price price, BigInteger minAmount, BigInteger maxAmount, int factor) {
        checkArgument(
                amount.longValueExact() >= Restrictions.getMinTradeAmount().longValueExact(),
                "amount must be above minimum of " + HavenoUtils.atomicUnitsToXmr(Restrictions.getMinTradeAmount()) + " xmr but was " + HavenoUtils.atomicUnitsToXmr(amount) + " xmr"
        );
        if (minAmount == null) minAmount = Restrictions.getMinTradeAmount();
        checkArgument(
                minAmount.longValueExact() >= Restrictions.getMinTradeAmount().longValueExact(),
                "minAmount must be above minimum of " + HavenoUtils.atomicUnitsToXmr(Restrictions.getMinTradeAmount()) + " xmr but was " + HavenoUtils.atomicUnitsToXmr(minAmount) + " xmr"
        );
        if (maxAmount != null) {
            checkArgument(
                amount.longValueExact() <= maxAmount.longValueExact(),
                "amount must be below maximum of " + HavenoUtils.atomicUnitsToXmr(maxAmount) + " xmr but was " + HavenoUtils.atomicUnitsToXmr(amount) + " xmr"
            );
            checkArgument(
                maxAmount.longValueExact() >= minAmount.longValueExact(),
                "maxAmount must be above minimum of " + HavenoUtils.atomicUnitsToXmr(Restrictions.getMinTradeAmount()) + " xmr but was " + HavenoUtils.atomicUnitsToXmr(maxAmount) + " xmr"
            );
        }

        checkArgument(
                factor > 0,
                "factor must be positive"
        );

        // Amount must result in a volume of min factor units of the fiat currency, e.g. 1 EUR or 10 EUR in case of HalCash.
        Volume smallestUnitForVolume = Volume.parse(String.valueOf(factor), price.getCurrencyCode());
        if (smallestUnitForVolume.getValue() <= 0) return BigInteger.ZERO;
        BigInteger smallestUnitForAmount = price.getAmountByVolume(smallestUnitForVolume);
        smallestUnitForAmount = BigInteger.valueOf(Math.max(minAmount.longValueExact(), smallestUnitForAmount.longValueExact()));

        // We get the adjusted volume from our amount
        boolean useSmallestUnitForAmount = amount.compareTo(smallestUnitForAmount) < 0;
        Volume volume = useSmallestUnitForAmount
                ? getAdjustedVolumeUnit(price.getVolumeByAmount(smallestUnitForAmount), factor)
                : getAdjustedVolumeUnit(price.getVolumeByAmount(amount), factor);
        if (volume.getValue() <= 0) return BigInteger.ZERO;

        // From that adjusted volume we calculate back the amount. It might be a bit different as
        // the amount used as input before due rounding.
        BigInteger amountByVolume = price.getAmountByVolume(volume);

        // For the amount we allow only 4 decimal places
        long adjustedAmount = HavenoUtils.centinerosToAtomicUnits(Math.round(HavenoUtils.atomicUnitsToCentineros(amountByVolume) / 10000d) * 10000).longValueExact();

        // If we are below the minAmount we increase the amount by the smallestUnitForAmount
        BigInteger smallestUnitForAmountUnadjusted = price.getAmountByVolume(smallestUnitForVolume);
        if (minAmount != null) {
            while (adjustedAmount < minAmount.longValueExact()) {
                adjustedAmount += smallestUnitForAmountUnadjusted.longValueExact();
            }
        }

        // If we are above our trade limit we reduce the amount by the smallestUnitForAmount
        if (maxAmount != null) {
            while (adjustedAmount > maxAmount.longValueExact()) {
                adjustedAmount -= smallestUnitForAmountUnadjusted.longValueExact();
            }
        }

        adjustedAmount = Math.max(minAmount.longValueExact(), adjustedAmount);
        if (maxAmount != null) adjustedAmount = Math.min(maxAmount.longValueExact(), adjustedAmount);
        return BigInteger.valueOf(adjustedAmount);
    }
}
