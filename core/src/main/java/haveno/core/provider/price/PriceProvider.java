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

package haveno.core.provider.price;

import com.google.gson.Gson;
import com.google.gson.internal.LinkedTreeMap;
import haveno.common.app.Version;
import haveno.common.util.MathUtils;
import haveno.core.locale.CurrencyUtil;
import haveno.core.provider.HttpClientProvider;
import haveno.network.http.HttpClient;
import haveno.network.p2p.P2PService;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Slf4j
public class PriceProvider extends HttpClientProvider {

    private boolean shutDownRequested;

    // Do not use Guice here as we might create multiple instances
    public PriceProvider(HttpClient httpClient, String baseUrl) {
        super(httpClient, baseUrl, false);
    }

    public synchronized Map<String, MarketPrice> getAll() throws IOException {
        if (shutDownRequested) {
            return new HashMap<>();
        }

        Map<String, MarketPrice> marketPriceMap = new HashMap<>();
        String hsVersion = "";
        if (P2PService.getMyNodeAddress() != null)
            hsVersion = P2PService.getMyNodeAddress().getHostName().length() > 22 ? ", HSv3" : ", HSv2";

        String json = httpClient.get("getAllMarketPrices", "User-Agent", "haveno/"
                + Version.VERSION + hsVersion);
        LinkedTreeMap<?, ?> map = new Gson().fromJson(json, LinkedTreeMap.class);

        List<?> list = (ArrayList<?>) map.get("data");
        list.forEach(obj -> {
            try {
                LinkedTreeMap<?, ?> treeMap = (LinkedTreeMap<?, ?>) obj;
                String baseCurrencyCode = (String) treeMap.get("baseCurrencyCode");
                String counterCurrencyCode = (String) treeMap.get("counterCurrencyCode");
                boolean isInverted = !"XMR".equalsIgnoreCase(baseCurrencyCode);
                if (isInverted) {
                    String temp = baseCurrencyCode;
                    baseCurrencyCode = counterCurrencyCode;
                    counterCurrencyCode = temp;
                }
                counterCurrencyCode = CurrencyUtil.getCurrencyCodeBase(counterCurrencyCode);
                double price = (Double) treeMap.get("price");
                if (isInverted) price = BigDecimal.ONE.divide(BigDecimal.valueOf(price), 10, RoundingMode.HALF_UP).doubleValue(); // XMR is always base currency, so invert price if applicable
                long timestampSec = MathUtils.doubleToLong((Double) treeMap.get("timestampSec"));
                marketPriceMap.put(counterCurrencyCode, new MarketPrice(counterCurrencyCode, price, timestampSec, true));
            } catch (Throwable t) {
                log.error("Error getting all prices: {}\n", t.getMessage(), t);
            }
        });
        return marketPriceMap;
    }

    public String getBaseUrl() {
        return httpClient.getBaseUrl();
    }

    public void shutDown() {
        shutDownRequested = true;
        httpClient.shutDown();
    }
}
