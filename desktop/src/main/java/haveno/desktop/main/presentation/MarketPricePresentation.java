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

package haveno.desktop.main.presentation;

import com.google.inject.Inject;
import com.google.inject.Singleton;
import haveno.common.UserThread;
import haveno.core.locale.CurrencyUtil;
import haveno.core.locale.Res;
import haveno.core.locale.TradeCurrency;
import haveno.core.provider.price.MarketPrice;
import haveno.core.provider.price.PriceFeedService;
import haveno.core.user.Preferences;
import haveno.core.util.FormattingUtils;
import haveno.core.xmr.wallet.XmrWalletService;
import haveno.desktop.components.TxIdTextField;
import haveno.desktop.main.shared.PriceFeedComboBoxItem;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javafx.beans.property.BooleanProperty;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.ObjectProperty;
import javafx.beans.property.SimpleBooleanProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleObjectProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ListChangeListener;
import javafx.collections.ObservableList;
import lombok.Getter;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;
import org.fxmisc.easybind.monadic.MonadicBinding;

@Singleton
public class MarketPricePresentation {
    private final Preferences preferences;
    private final PriceFeedService priceFeedService;
    @Getter
    private final ObservableList<PriceFeedComboBoxItem> priceFeedComboBoxItems = FXCollections.observableArrayList();
    @SuppressWarnings("FieldCanBeLocal")
    private MonadicBinding<String> marketPriceBinding;
    @SuppressWarnings({"FieldCanBeLocal", "unused"})
    private Subscription priceFeedAllLoadedSubscription;

    private final StringProperty marketPriceCurrencyCode = new SimpleStringProperty("");
    private final ObjectProperty<PriceFeedComboBoxItem> selectedPriceFeedComboBoxItemProperty = new SimpleObjectProperty<>();
    private final BooleanProperty isFiatCurrencyPriceFeedSelected = new SimpleBooleanProperty(true);
    private final BooleanProperty isCryptoCurrencyPriceFeedSelected = new SimpleBooleanProperty(false);
    private final BooleanProperty isExternallyProvidedPrice = new SimpleBooleanProperty(true);
    private final BooleanProperty isPriceAvailable = new SimpleBooleanProperty(false);
    private final IntegerProperty marketPriceUpdated = new SimpleIntegerProperty(0);
    private final StringProperty marketPrice = new SimpleStringProperty(Res.get("shared.na"));


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Inject
    public MarketPricePresentation(XmrWalletService xmrWalletService,
                                   PriceFeedService priceFeedService,
                                   Preferences preferences) {
        this.priceFeedService = priceFeedService;
        this.preferences = preferences;

        TxIdTextField.setPreferences(preferences);

        TxIdTextField.setXmrWalletService(xmrWalletService);
    }

    public void setup() {
        fillPriceFeedComboBoxItems();
        setupMarketPriceFeed();

    }

    public void setPriceFeedComboBoxItem(PriceFeedComboBoxItem item) {
        if (item != null) {
            Optional<PriceFeedComboBoxItem> itemOptional = findPriceFeedComboBoxItem(priceFeedService.currencyCodeProperty().get());
            if (itemOptional.isPresent())
                selectedPriceFeedComboBoxItemProperty.set(itemOptional.get());
            else
                findPriceFeedComboBoxItem(preferences.getPreferredTradeCurrency().getCode())
                        .ifPresent(selectedPriceFeedComboBoxItemProperty::set);

            priceFeedService.setCurrencyCode(item.currencyCode);
        } else {
            findPriceFeedComboBoxItem(preferences.getPreferredTradeCurrency().getCode())
                    .ifPresent(selectedPriceFeedComboBoxItemProperty::set);
        }
    }

    private void fillPriceFeedComboBoxItems() {

        // collect unique currency code bases
        List<String> uniqueCurrencyCodeBases = preferences.getTradeCurrenciesAsObservable()
                .stream()
                .map(TradeCurrency::getCode)
                .map(CurrencyUtil::getCurrencyCodeBase)
                .distinct()
                .collect(Collectors.toList());

        // create price feed items
        List<PriceFeedComboBoxItem> currencyItems = uniqueCurrencyCodeBases
                .stream()
                .map(currencyCodeBase -> new PriceFeedComboBoxItem(currencyCodeBase))
                .collect(Collectors.toList());
        priceFeedComboBoxItems.setAll(currencyItems);
    }

    private void setupMarketPriceFeed() {
        priceFeedService.startRequestingPrices(price -> marketPrice.set(FormattingUtils.formatMarketPrice(price, priceFeedService.getCurrencyCode())),
                (errorMessage, throwable) -> marketPrice.set(Res.get("shared.na")));

        marketPriceBinding = EasyBind.combine(
                marketPriceCurrencyCode, marketPrice,
                (currencyCode, price) -> {
                    MarketPrice currentPrice = priceFeedService.getMarketPrice(currencyCode);
                    String currentPriceStr = currentPrice == null ? Res.get("shared.na") : FormattingUtils.formatMarketPrice(currentPrice.getPrice(), currencyCode);
                    return CurrencyUtil.getCurrencyPair(currencyCode) + ": " + currentPriceStr;
                });

        marketPriceBinding.subscribe((observable, oldValue, newValue) -> {
            UserThread.execute(() -> {
                if (newValue != null && !newValue.equals(oldValue)) {
                    setMarketPriceInItems();

                    String code = priceFeedService.currencyCodeProperty().get();
                    Optional<PriceFeedComboBoxItem> itemOptional = findPriceFeedComboBoxItem(code);
                    if (itemOptional.isPresent()) {
                        itemOptional.get().setDisplayString(newValue);
                        selectedPriceFeedComboBoxItemProperty.set(itemOptional.get());
                    } else {
                        if (CurrencyUtil.isCryptoCurrency(code)) {
                            CurrencyUtil.getCryptoCurrency(code).ifPresent(cryptoCurrency -> {
                                preferences.addCryptoCurrency(cryptoCurrency);
                                fillPriceFeedComboBoxItems();
                            });
                        } else {
                            CurrencyUtil.getTraditionalCurrency(code).ifPresent(traditionalCurrency -> {
                                preferences.addTraditionalCurrency(traditionalCurrency);
                                fillPriceFeedComboBoxItems();
                            });
                        }
                    }

                    if (selectedPriceFeedComboBoxItemProperty.get() != null)
                        selectedPriceFeedComboBoxItemProperty.get().setDisplayString(newValue);
                }
            });
        });

        marketPriceCurrencyCode.bind(priceFeedService.currencyCodeProperty());

        priceFeedAllLoadedSubscription = EasyBind.subscribe(priceFeedService.updateCounterProperty(), updateCounter -> UserThread.execute(() -> setMarketPriceInItems()));

        preferences.getTradeCurrenciesAsObservable().addListener((ListChangeListener<TradeCurrency>) c -> UserThread.runAfter(() -> {
            fillPriceFeedComboBoxItems();
            setMarketPriceInItems();
        }, 100, TimeUnit.MILLISECONDS));
    }

    private Optional<PriceFeedComboBoxItem> findPriceFeedComboBoxItem(String currencyCode) {
        return priceFeedComboBoxItems.stream()
                .filter(item -> CurrencyUtil.getCurrencyCodeBase(item.currencyCode).equals(CurrencyUtil.getCurrencyCodeBase(currencyCode)))
                .findAny();
    }

    private void setMarketPriceInItems() {
        priceFeedComboBoxItems.forEach(item -> {
            String currencyCode = item.currencyCode;
            MarketPrice marketPrice = priceFeedService.getMarketPrice(currencyCode);
            String priceString;
            if (marketPrice != null && marketPrice.isPriceAvailable()) {
                priceString = FormattingUtils.formatMarketPrice(marketPrice.getPrice(), currencyCode);
                item.setPriceAvailable(true);
                item.setExternallyProvidedPrice(marketPrice.isExternallyProvidedPrice());
            } else {
                priceString = Res.get("shared.na");
                item.setPriceAvailable(false);
            }
            item.setDisplayString(CurrencyUtil.getCurrencyPair(currencyCode) + ": " + priceString);

            final String code = item.currencyCode;
            if (selectedPriceFeedComboBoxItemProperty.get() != null &&
                    selectedPriceFeedComboBoxItemProperty.get().currencyCode.equals(code)) {
                isFiatCurrencyPriceFeedSelected.set(CurrencyUtil.isTraditionalCurrency(code) && CurrencyUtil.getTraditionalCurrency(code).isPresent() && item.isPriceAvailable() && item.isExternallyProvidedPrice());
                isCryptoCurrencyPriceFeedSelected.set(CurrencyUtil.isCryptoCurrency(code) && CurrencyUtil.getCryptoCurrency(code).isPresent() && item.isPriceAvailable() && item.isExternallyProvidedPrice());
                isExternallyProvidedPrice.set(item.isExternallyProvidedPrice());
                isPriceAvailable.set(item.isPriceAvailable());
                marketPriceUpdated.set(marketPriceUpdated.get() + 1);
            }
        });
    }

    public ObjectProperty<PriceFeedComboBoxItem> getSelectedPriceFeedComboBoxItemProperty() {
        return selectedPriceFeedComboBoxItemProperty;
    }

    public BooleanProperty getIsFiatCurrencyPriceFeedSelected() {
        return isFiatCurrencyPriceFeedSelected;
    }

    public BooleanProperty getIsCryptoCurrencyPriceFeedSelected() {
        return isCryptoCurrencyPriceFeedSelected;
    }

    public BooleanProperty getIsExternallyProvidedPrice() {
        return isExternallyProvidedPrice;
    }

    public BooleanProperty getIsPriceAvailable() {
        return isPriceAvailable;
    }

    public IntegerProperty getMarketPriceUpdated() {
        return marketPriceUpdated;
    }

    public StringProperty getMarketPrice() {
        return marketPrice;
    }

    public StringProperty getMarketPrice(String currencyCode) {
        SimpleStringProperty marketPrice = new SimpleStringProperty(Res.get("shared.na"));
        MarketPrice marketPriceValue = priceFeedService.getMarketPrice(currencyCode);
        // Market price might not be available yet:
        if (marketPriceValue != null) {
            marketPrice.set(String.valueOf(marketPriceValue.getPrice()));
        }
        return marketPrice;
    }
}
