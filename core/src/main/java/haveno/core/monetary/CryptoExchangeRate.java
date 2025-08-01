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

package haveno.core.monetary;

import lombok.extern.slf4j.Slf4j;
import org.bitcoinj.core.Coin;

import java.math.BigInteger;

import static com.google.common.base.Preconditions.checkArgument;

// Cloned from ExchangeRate. Use Crypto instead of Fiat.
@Slf4j
public class CryptoExchangeRate {
    /**
     * An exchange rate is expressed as a ratio of a {@link Coin} and a {@link CryptoMoney} amount.
     */

    public final Coin coin;
    public final CryptoMoney cryptoMoney;

    /**
     * Construct exchange rate. This amount of coin is worth that amount of crypto.
     */
    @SuppressWarnings("SameParameterValue")
    public CryptoExchangeRate(Coin coin, CryptoMoney crypto) {
        checkArgument(coin.isPositive());
        checkArgument(crypto.isPositive());
        checkArgument(crypto.currencyCode != null, "currency code required");
        this.coin = coin;
        this.cryptoMoney = crypto;
    }

    /**
     * Construct exchange rate. One coin is worth this amount of crypto.
     */
    public CryptoExchangeRate(CryptoMoney crypto) {
        this(Coin.COIN, crypto);
    }

    /**
     * Convert a coin amount to an crypto amount using this exchange rate.
     *
     * @throws ArithmeticException if the converted crypto amount is too high or too low.
     */
    public CryptoMoney coinToCrypto(Coin convertCoin) {
        final BigInteger converted = BigInteger.valueOf(convertCoin.value)
                .multiply(BigInteger.valueOf(cryptoMoney.value))
                .divide(BigInteger.valueOf(coin.value));
        if (converted.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || converted.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0)
            throw new ArithmeticException("Overflow");
        return CryptoMoney.valueOf(cryptoMoney.currencyCode, converted.longValue());
    }

    /**
     * Convert a crypto amount to a coin amount using this exchange rate.
     *
     * @throws ArithmeticException if the converted coin amount is too high or too low.
     */
    public Coin cryptoToCoin(CryptoMoney convertCrypto) {
        checkArgument(convertCrypto.currencyCode.equals(cryptoMoney.currencyCode), "Currency mismatch: %s vs %s",
                convertCrypto.currencyCode, cryptoMoney.currencyCode);
        // Use BigInteger because it's much easier to maintain full precision without overflowing.
        final BigInteger converted = BigInteger.valueOf(convertCrypto.value).multiply(BigInteger.valueOf(coin.value))
                .divide(BigInteger.valueOf(cryptoMoney.value));
        if (converted.compareTo(BigInteger.valueOf(Long.MAX_VALUE)) > 0
                || converted.compareTo(BigInteger.valueOf(Long.MIN_VALUE)) < 0)
            throw new ArithmeticException("Overflow");
        try {
            return Coin.valueOf(converted.longValue());
        } catch (IllegalArgumentException x) {
            throw new ArithmeticException("Overflow: " + x.getMessage());
        }
    }
}
