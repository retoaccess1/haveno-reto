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

package haveno.desktop.main.market.offerbook;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import com.jfoenix.controls.JFXTabPane;
import haveno.common.UserThread;
import haveno.common.config.Config;
import haveno.common.util.Tuple3;
import haveno.common.util.Tuple4;
import haveno.core.locale.CurrencyUtil;
import haveno.core.locale.Res;
import haveno.core.monetary.Volume;
import haveno.core.offer.Offer;
import haveno.core.offer.OfferDirection;
import haveno.core.util.FormattingUtils;
import haveno.core.util.VolumeUtil;
import haveno.core.util.coin.CoinFormatter;
import haveno.desktop.common.view.ActivatableViewAndModel;
import haveno.desktop.common.view.FxmlView;
import haveno.desktop.components.AutoTooltipButton;
import haveno.desktop.components.AutoTooltipLabel;
import haveno.desktop.components.AutoTooltipTableColumn;
import haveno.desktop.components.AutocompleteComboBox;
import haveno.desktop.components.ColoredDecimalPlacesWithZerosText;
import haveno.desktop.components.PeerInfoIconSmall;
import haveno.desktop.main.offer.offerbook.OfferBookListItem;
import haveno.desktop.util.CurrencyListItem;
import haveno.desktop.util.DisplayUtils;
import static haveno.desktop.util.FormBuilder.addTopLabelAutocompleteComboBox;
import haveno.desktop.util.GUIUtil;
import static haveno.desktop.util.Layout.INITIAL_WINDOW_HEIGHT;
import haveno.network.p2p.NodeAddress;
import java.text.DecimalFormat;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.beans.value.ChangeListener;
import javafx.beans.value.ObservableValue;
import javafx.collections.ListChangeListener;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.geometry.Side;
import javafx.scene.chart.AreaChart;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.ContentDisplay;
import javafx.scene.control.Label;
import javafx.scene.control.SingleSelectionModel;
import javafx.scene.control.Tab;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.Region;
import javafx.scene.layout.VBox;
import javafx.util.Callback;
import javafx.util.StringConverter;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;

@FxmlView
public class OfferBookChartView extends ActivatableViewAndModel<VBox, OfferBookChartViewModel> {
    private final boolean useDevPrivilegeKeys;

    private NumberAxis xAxis;
    private XYChart.Series<Number, Number> seriesBuy, seriesSell;
    private final CoinFormatter formatter;
    private TableView<OfferListItem> buyOfferTableView;
    private TableView<OfferListItem> sellOfferTableView;
    private AreaChart<Number, Number> areaChart;
    private AnchorPane chartPane;
    private AutocompleteComboBox<CurrencyListItem> currencyComboBox;
    private Subscription tradeCurrencySubscriber;
    private final StringProperty volumeSellColumnLabel = new SimpleStringProperty();
    private final StringProperty volumeBuyColumnLabel = new SimpleStringProperty();
    private final StringProperty amountSellColumnLabel = new SimpleStringProperty();
    private final StringProperty amountBuyColumnLabel = new SimpleStringProperty();
    private final StringProperty priceColumnLabel = new SimpleStringProperty();
    private AutoTooltipButton sellButton;
    private AutoTooltipButton buyButton;
    private ChangeListener<Number> selectedTabIndexListener;
    private SingleSelectionModel<Tab> tabPaneSelectionModel;
    private Label sellHeaderLabel, buyHeaderLabel;
    private ChangeListener<OfferListItem> sellTableRowSelectionListener, buyTableRowSelectionListener;
    private ListChangeListener<OfferBookListItem> changeListener;
    private ListChangeListener<CurrencyListItem> currencyListItemsListener;
    private final double dataLimitFactor = 3;
    private final double initialOfferTableViewHeight = 78; // decrease as MainView's content-pane's top anchor increases
    private final double offerTableExtraMarginBottom = 0;
    private final Function<Double, Double> offerTableViewHeight = (screenSize) -> {
        // initial visible row count=5, header height=30
        double pixelsPerOfferTableRow = (initialOfferTableViewHeight - offerTableExtraMarginBottom) / 5.0;
        int extraRows = screenSize <= INITIAL_WINDOW_HEIGHT ? 0 : (int) ((screenSize - INITIAL_WINDOW_HEIGHT) / pixelsPerOfferTableRow);
        return extraRows == 0 ? initialOfferTableViewHeight : Math.ceil(initialOfferTableViewHeight + ((extraRows + 1) * pixelsPerOfferTableRow));
    };
    private ChangeListener<Number> havenoWindowVerticalSizeListener;

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor, lifecycle
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Inject
    public OfferBookChartView(OfferBookChartViewModel model,
                              @Named(FormattingUtils.BTC_FORMATTER_KEY) CoinFormatter formatter,
                              @Named(Config.USE_DEV_PRIVILEGE_KEYS) boolean useDevPrivilegeKeys) {
        super(model);
        this.formatter = formatter;
        this.useDevPrivilegeKeys = useDevPrivilegeKeys;
    }

    @Override
    public void initialize() {
        createListener();

        final Tuple3<VBox, Label, AutocompleteComboBox<CurrencyListItem>> currencyComboBoxTuple = addTopLabelAutocompleteComboBox(Res.get("shared.currency"), 0);
        this.currencyComboBox = currencyComboBoxTuple.third;
        this.currencyComboBox.setCellFactory(GUIUtil.getCurrencyListItemCellFactory(Res.get("shared.oneOffer"),
                Res.get("shared.multipleOffers"), model.preferences));
        this.currencyComboBox.getStyleClass().add("input-with-border");

        createChart();

        VBox.setMargin(chartPane, new Insets(0, 0, 5, 0));

        Tuple4<TableView<OfferListItem>, VBox, Button, Label> tupleBuy = getOfferTable(OfferDirection.BUY);
        Tuple4<TableView<OfferListItem>, VBox, Button, Label> tupleSell = getOfferTable(OfferDirection.SELL);
        buyOfferTableView = tupleBuy.first;
        sellOfferTableView = tupleSell.first;

        sellButton = (AutoTooltipButton) tupleBuy.third;
        buyButton = (AutoTooltipButton) tupleSell.third;

        sellHeaderLabel = tupleBuy.fourth;
        buyHeaderLabel = tupleSell.fourth;

        HBox bottomHBox = new HBox();
        bottomHBox.setSpacing(20); //30
        bottomHBox.setAlignment(Pos.CENTER);
        VBox.setMargin(bottomHBox, new Insets(-5, 0, 0, 0));
        HBox.setHgrow(tupleBuy.second, Priority.ALWAYS);
        HBox.setHgrow(tupleSell.second, Priority.ALWAYS);
        tupleBuy.second.setUserData(OfferDirection.BUY.name());
        tupleSell.second.setUserData(OfferDirection.SELL.name());
        bottomHBox.getChildren().addAll(tupleSell.second, tupleBuy.second);

        root.getChildren().addAll(currencyComboBoxTuple.first, chartPane, bottomHBox);
    }

    @Override
    protected void activate() {
        // root.getParent() is null at initialize
        tabPaneSelectionModel = GUIUtil.getParentOfType(root, JFXTabPane.class).getSelectionModel();
        selectedTabIndexListener = (observable, oldValue, newValue) -> model.setSelectedTabIndex((int) newValue);

        model.setSelectedTabIndex(tabPaneSelectionModel.getSelectedIndex());
        tabPaneSelectionModel.selectedIndexProperty().addListener(selectedTabIndexListener);

        currencyComboBox.setConverter(new CurrencyListItemStringConverter(currencyComboBox));
        currencyComboBox.getEditor().getStyleClass().add("combo-box-editor-bold");

        currencyComboBox.setAutocompleteItems(model.getCurrencyListItems());
        currencyComboBox.setVisibleRowCount(10);

        if (model.getSelectedCurrencyListItem().isPresent()) {
            CurrencyListItem selectedItem = model.getSelectedCurrencyListItem().get();
            currencyComboBox.getSelectionModel().select(model.getSelectedCurrencyListItem().get());
            currencyComboBox.getEditor().setText(new CurrencyListItemStringConverter(currencyComboBox).toString(selectedItem));
        }

        currencyComboBox.setOnChangeConfirmed(e -> {
            CurrencyListItem selectedItem = currencyComboBox.getSelectionModel().getSelectedItem();
            if (selectedItem != null) {
                model.onSetTradeCurrency(selectedItem.tradeCurrency);
                UserThread.execute(() -> updateChartData());
            }
        });

        model.currencyListItems.getObservableList().addListener(currencyListItemsListener);

        model.getOfferBookListItems().addListener(changeListener);
        tradeCurrencySubscriber = EasyBind.subscribe(model.selectedTradeCurrencyProperty,
                tradeCurrency -> {
                    String code = tradeCurrency.getCode();
                    xAxis.setTickLabelFormatter(new StringConverter<>() {
                        final int cryptoPrecision = 3;
                        final DecimalFormat df = new DecimalFormat(",###");

                        @Override
                        public String toString(Number object) {
                            try {
                                final double doubleValue = (double) object;
                                if (CurrencyUtil.isCryptoCurrency(model.getCurrencyCode())) {
                                    final String withCryptoPrecision = FormattingUtils.formatRoundedDoubleWithPrecision(doubleValue, cryptoPrecision);
                                    if (withCryptoPrecision.startsWith("0.0")) {
                                        return FormattingUtils.formatRoundedDoubleWithPrecision(doubleValue, 8).replaceFirst("0+$", "");
                                    } else {
                                        return withCryptoPrecision.replaceFirst("0+$", "");
                                    }
                                } else {
                                    return df.format(Double.parseDouble(FormattingUtils.formatRoundedDoubleWithPrecision(doubleValue, 0)));
                                }
                            } catch (IllegalArgumentException e) {
                                log.error("Error converting number to string, tradeCurrency={}, number={}\n", code, object, e);
                                return "NaN"; // TODO: occasionally getting invalid number
                            }
                        }

                        @Override
                        public Number fromString(String string) {
                            return null;
                        }
                    });
                    
                    String viewBaseCurrencyCode = Res.getBaseCurrencyCode();
                    String viewPriceCurrencyCode = code;

                    sellHeaderLabel.setText(Res.get("market.offerBook.sellOffersHeaderLabel", viewBaseCurrencyCode));
                    sellButton.updateText(Res.get("shared.sellCurrency", viewBaseCurrencyCode));
                    sellButton.setGraphic(GUIUtil.getCurrencyIconWithBorder(viewBaseCurrencyCode));
                    sellButton.setOnAction(e -> model.goToOfferView(OfferDirection.BUY));
                    sellButton.setId("sell-button-big");

                    buyHeaderLabel.setText(Res.get("market.offerBook.buyOffersHeaderLabel", viewBaseCurrencyCode));
                    buyButton.updateText(Res.get( "shared.buyCurrency", viewBaseCurrencyCode));
                    buyButton.setGraphic(GUIUtil.getCurrencyIconWithBorder(viewBaseCurrencyCode));
                    buyButton.setOnAction(e -> model.goToOfferView(OfferDirection.SELL));
                    buyButton.setId("buy-button-big");

                    priceColumnLabel.set(Res.get("shared.priceWithCur", viewPriceCurrencyCode));

                    xAxis.setLabel(CurrencyUtil.getPriceWithCurrencyCode(code));

                    seriesBuy.setName(sellHeaderLabel.getText() + "   ");
                    seriesSell.setName(buyHeaderLabel.getText());
                });

        buyOfferTableView.setItems(model.getTopBuyOfferList());
        sellOfferTableView.setItems(model.getTopSellOfferList());

        buyOfferTableView.getSelectionModel().selectedItemProperty().addListener(buyTableRowSelectionListener);
        sellOfferTableView.getSelectionModel().selectedItemProperty().addListener(sellTableRowSelectionListener);

        root.getScene().heightProperty().addListener(havenoWindowVerticalSizeListener);
        layout();

        updateChartData();
    }

    static class CurrencyListItemStringConverter extends StringConverter<CurrencyListItem> {
        private final ComboBox<CurrencyListItem> comboBox;

        CurrencyListItemStringConverter(ComboBox<CurrencyListItem> comboBox) {
            this.comboBox = comboBox;
        }

        @Override
        public String toString(CurrencyListItem currencyItem) {
            return currencyItem != null ? currencyItem.codeDashNameString() : "";
        }

        @Override
        public CurrencyListItem fromString(String s) {
            return comboBox.getItems().stream().
                    filter(currencyItem -> currencyItem.codeDashNameString().equals(s)).
                    findAny().orElse(null);
        }
    }

    private void createListener() {
        changeListener = c -> UserThread.execute(() -> updateChartData());

        currencyListItemsListener = c -> {
            if (model.getSelectedCurrencyListItem().isPresent())
                currencyComboBox.getSelectionModel().select(model.getSelectedCurrencyListItem().get());
        };

        sellTableRowSelectionListener = (observable, oldValue, newValue) -> model.goToOfferView(OfferDirection.SELL);
        buyTableRowSelectionListener = (observable, oldValue, newValue) -> model.goToOfferView(OfferDirection.BUY);

        havenoWindowVerticalSizeListener = (observable, oldValue, newValue) -> layout();
    }

    @Override
    protected void deactivate() {
        model.getOfferBookListItems().removeListener(changeListener);
        tabPaneSelectionModel.selectedIndexProperty().removeListener(selectedTabIndexListener);
        model.currencyListItems.getObservableList().removeListener(currencyListItemsListener);
        tradeCurrencySubscriber.unsubscribe();
        buyOfferTableView.getSelectionModel().selectedItemProperty().removeListener(buyTableRowSelectionListener);
        sellOfferTableView.getSelectionModel().selectedItemProperty().removeListener(sellTableRowSelectionListener);
    }

    private void createChart() {
        xAxis = new NumberAxis();
        xAxis.setForceZeroInRange(false);
        xAxis.setAutoRanging(true);
        xAxis.setTickMarkVisible(true);
        xAxis.setMinorTickVisible(false);

        NumberAxis yAxis = new NumberAxis();
        yAxis.setForceZeroInRange(false);
        yAxis.setSide(Side.RIGHT);
        yAxis.setAutoRanging(true);
        yAxis.setTickMarkVisible(true);
        yAxis.setMinorTickVisible(false);
        yAxis.getStyleClass().add("axisy");
        yAxis.setLabel(CurrencyUtil.getOfferVolumeCode(Res.getBaseCurrencyCode()));

        seriesBuy = new XYChart.Series<>();
        seriesSell = new XYChart.Series<>();

        areaChart = new AreaChart<>(xAxis, yAxis);
        areaChart.setLegendVisible(false);
        areaChart.setAnimated(false);
        areaChart.setId("charts");
        areaChart.setMinHeight(270);
        areaChart.setPrefHeight(270);
        areaChart.setCreateSymbols(true);
        areaChart.setPadding(new Insets(0, 10, 0, 10));
        areaChart.getData().addAll(List.of(seriesBuy, seriesSell));

        chartPane = new AnchorPane();
        chartPane.getStyleClass().add("chart-pane");

        AnchorPane.setTopAnchor(areaChart, 15d);
        AnchorPane.setBottomAnchor(areaChart, 10d);
        AnchorPane.setLeftAnchor(areaChart, 10d);
        AnchorPane.setRightAnchor(areaChart, 0d);

        chartPane.getChildren().add(areaChart);
    }

    private synchronized void updateChartData() {

        // update volume headers
        Volume volumeSell = model.getTotalVolume(OfferDirection.SELL);
        Volume volumeBuy = model.getTotalVolume(OfferDirection.BUY);
        String formattedVolumeSell = volumeSell == null ? null : VolumeUtil.formatVolume(volumeSell);
        String formattedVolumeBuy = volumeBuy == null ? null : VolumeUtil.formatVolume(volumeBuy);
        if (model.getSellData().isEmpty()) formattedVolumeSell = "0.0";
        if (model.getBuyData().isEmpty()) formattedVolumeBuy = "0.0";
        volumeSellColumnLabel.set(Res.get("offerbook.volumeTotal", model.getCurrencyCode(), formattedVolumeSell == null ? "" : "(" + formattedVolumeSell + ")"));
        volumeBuyColumnLabel.set(Res.get("offerbook.volumeTotal", model.getCurrencyCode(), formattedVolumeBuy == null ? "" : "(" + formattedVolumeBuy + ")"));

        // update amount headers
        amountSellColumnLabel.set(Res.get("offerbook.XMRTotal", "" + model.getTotalAmount(OfferDirection.SELL)));
        amountBuyColumnLabel.set(Res.get("offerbook.XMRTotal", "" + model.getTotalAmount(OfferDirection.BUY)));

        seriesSell.getData().clear();
        seriesBuy.getData().clear();
        areaChart.getData().clear();

        seriesSell.getData().addAll(filterOutliersSell(model.getSellData()));
        seriesBuy.getData().addAll(filterOutliersBuy(model.getBuyData()));

        areaChart.getData().addAll(List.of(seriesBuy, seriesSell));
    }

    List<XYChart.Data<Number, Number>> filterOutliersBuy(List<XYChart.Data<Number, Number>> buy) {
        List<Double> mnmx = minMaxFilterLeft(buy);
        if (mnmx.get(0) == Double.MAX_VALUE ||
                mnmx.get(1) == Double.MIN_VALUE) { // no filtering
            return buy;
        }
        // apply filtering
        return filterLeft(buy, mnmx.get(1));
    }

    List<XYChart.Data<Number, Number>> filterOutliersSell(List<XYChart.Data<Number, Number>> sell) {
        List<Double> mnmx = minMaxFilterRight(sell);
        if (mnmx.get(0) == Double.MAX_VALUE ||
                mnmx.get(1) == Double.MIN_VALUE) { // no filtering
            return sell;
        }
        // apply filtering
        return filterRight(sell, mnmx.get(0));
    }

    private List<Double> minMaxFilterLeft(List<XYChart.Data<Number, Number>> data) {
        synchronized (data) {
            double maxValue = data.stream()
                    .mapToDouble(o -> o.getXValue().doubleValue())
                    .max()
                    .orElse(Double.MIN_VALUE);
            // Hide offers less than a div-factor of dataLimitFactor lower than the highest offer.
            double minValue = data.stream()
                    .mapToDouble(o -> o.getXValue().doubleValue())
                    .filter(o -> o > maxValue / dataLimitFactor)
                    .min()
                    .orElse(Double.MAX_VALUE);
            return List.of(minValue, maxValue);
        }
    }

    private List<Double> minMaxFilterRight(List<XYChart.Data<Number, Number>> data) {
        synchronized (data) {
            double minValue = data.stream()
                    .mapToDouble(o -> o.getXValue().doubleValue())
                    .min()
                    .orElse(Double.MAX_VALUE);

            // Hide offers a dataLimitFactor factor higher than the lowest offer
            double maxValue = data.stream()
                    .mapToDouble(o -> o.getXValue().doubleValue())
                    .filter(o -> o < minValue * dataLimitFactor)
                    .max()
                    .orElse(Double.MIN_VALUE);
            return List.of(minValue, maxValue);
        }
    }

    private List<XYChart.Data<Number, Number>> filterLeft(List<XYChart.Data<Number, Number>> data, double maxValue) {
        synchronized (data) {
            return data.stream()
                    .filter(o -> o.getXValue().doubleValue() > maxValue / dataLimitFactor)
                    .collect(Collectors.toList());
        }
    }

    private List<XYChart.Data<Number, Number>> filterRight(List<XYChart.Data<Number, Number>> data, double minValue) {
        synchronized (data) {
            return data.stream()
                    .filter(o -> o.getXValue().doubleValue() < minValue * dataLimitFactor)
                    .collect(Collectors.toList());
        }
    }

    private Tuple4<TableView<OfferListItem>, VBox, Button, Label> getOfferTable(OfferDirection direction) {
        TableView<OfferListItem> tableView = new TableView<>();
        GUIUtil.applyTableStyle(tableView, false);
        tableView.setMinHeight(initialOfferTableViewHeight);
        tableView.setPrefHeight(initialOfferTableViewHeight);
        tableView.setMinWidth(480);
        tableView.getStyleClass().addAll("offer-table", "non-interactive-table");

        // price
        TableColumn<OfferListItem, OfferListItem> priceColumn = new TableColumn<>();
        priceColumn.textProperty().bind(priceColumnLabel);
        priceColumn.setMinWidth(115);
        priceColumn.setMaxWidth(115);
        priceColumn.setSortable(false);
        priceColumn.getStyleClass().add("number-column");
        priceColumn.setCellValueFactory((offer) -> new ReadOnlyObjectWrapper<>(offer.getValue()));
        priceColumn.setCellFactory(
                new Callback<>() {
                    @Override
                    public TableCell<OfferListItem, OfferListItem> call(TableColumn<OfferListItem, OfferListItem> column) {
                        return new TableCell<>() {
                            private Offer offer;
                            final ChangeListener<Number> listener = new ChangeListener<>() {
                                @Override
                                public void changed(ObservableValue<? extends Number> observable,
                                                    Number oldValue,
                                                    Number newValue) {
                                    if (offer != null && offer.getPrice() != null) {
                                        setText("");
                                        setGraphic(new ColoredDecimalPlacesWithZerosText(model.getPrice(offer),
                                                model.getZeroDecimalsForPrice(offer)));
                                        model.priceFeedService.updateCounterProperty().removeListener(listener);
                                    }
                                }
                            };

                            @Override
                            public void updateItem(final OfferListItem offerListItem, boolean empty) {
                                super.updateItem(offerListItem, empty);
                                if (offerListItem != null && !empty) {

                                    final Offer offer = offerListItem.offer;
                                    if (offer.getPrice() == null) {
                                        this.offer = offer;
                                        model.priceFeedService.updateCounterProperty().addListener(listener);
                                        setText(Res.get("shared.na"));
                                    } else {
                                        setGraphic(new ColoredDecimalPlacesWithZerosText(model.getPrice(offer),
                                                model.getZeroDecimalsForPrice(offer)));
                                    }
                                } else {
                                    model.priceFeedService.updateCounterProperty().removeListener(listener);
                                    this.offer = null;
                                    setText("");
                                    setGraphic(null);
                                }
                            }
                        };
                    }
                });

        boolean isSellTable = model.isSellOffer(direction);

        // volume
        TableColumn<OfferListItem, OfferListItem> volumeColumn = new TableColumn<>();
        volumeColumn.setMinWidth(115);
        volumeColumn.setSortable(false);
        volumeColumn.textProperty().bind(isSellTable ? volumeSellColumnLabel : volumeBuyColumnLabel);
        volumeColumn.getStyleClass().addAll("number-column");
        volumeColumn.setCellValueFactory((offer) -> new ReadOnlyObjectWrapper<>(offer.getValue()));
        volumeColumn.setCellFactory(
                new Callback<>() {
                    @Override
                    public TableCell<OfferListItem, OfferListItem> call(TableColumn<OfferListItem, OfferListItem> column) {
                        return new TableCell<>() {
                            private Offer offer;
                            final ChangeListener<Number> listener = new ChangeListener<>() {
                                @Override
                                public void changed(ObservableValue<? extends Number> observable,
                                                    Number oldValue,
                                                    Number newValue) {
                                    if (offer != null && offer.getPrice() != null) {
                                        renderCellContentRange();
                                        model.priceFeedService.updateCounterProperty().removeListener(listener);
                                    }
                                }
                            };

                            @Override
                            public void updateItem(final OfferListItem offerListItem, boolean empty) {
                                super.updateItem(offerListItem, empty);
                                if (offerListItem != null && !empty) {
                                    this.offer = offerListItem.offer;
                                    if (offer.getPrice() == null) {
                                        this.offer = offerListItem.offer;
                                        model.priceFeedService.updateCounterProperty().addListener(listener);
                                        setText(Res.get("shared.na"));
                                    } else {
                                        renderCellContentRange();
                                    }
                                } else {
                                    model.priceFeedService.updateCounterProperty().removeListener(listener);
                                    this.offer = null;
                                    setText("");
                                    setGraphic(null);
                                }
                            }

                            /**
                             * Renders cell content, if it has a single value or a range.
                             * Should not be called for empty cells
                             */
                            private void renderCellContentRange() {
                                String volumeRange = VolumeUtil.formatVolume(offer, true, 2);

                                setText("");
                                setGraphic(new ColoredDecimalPlacesWithZerosText(volumeRange,
                                        model.getMaxNumberOfPriceZeroDecimalsToColorize(offer)));
                            }

                        };
                    }
                });

        // amount
        TableColumn<OfferListItem, OfferListItem> amountColumn = new TableColumn<>();
        amountColumn.textProperty().bind(isSellTable ? amountSellColumnLabel : amountBuyColumnLabel);
        amountColumn.setMinWidth(115);
        amountColumn.setSortable(false);
        amountColumn.getStyleClass().add("number-column");
        amountColumn.setCellValueFactory((offer) -> new ReadOnlyObjectWrapper<>(offer.getValue()));
        amountColumn.setCellFactory(
                new Callback<>() {
                    @Override
                    public TableCell<OfferListItem, OfferListItem> call(TableColumn<OfferListItem, OfferListItem> column) {
                        return new TableCell<>() {
                            @Override
                            public void updateItem(final OfferListItem offerListItem, boolean empty) {
                                super.updateItem(offerListItem, empty);
                                if (offerListItem != null && !empty) {
                                    String amountRange = DisplayUtils.formatAmount(offerListItem.offer, formatter);
                                    setGraphic(new ColoredDecimalPlacesWithZerosText(amountRange, GUIUtil.AMOUNT_DECIMALS_WITH_ZEROS));
                                } else {
                                    setGraphic(null);
                                }
                            }
                        };
                    }
                });

        // trader avatar
        TableColumn<OfferListItem, OfferListItem> avatarColumn = new AutoTooltipTableColumn<>(isSellTable ?
                Res.get("shared.sellerUpperCase") : Res.get("shared.buyerUpperCase")) {
            {
                setMinWidth(80);
                setMaxWidth(80);
                setSortable(true);
            }
        };

        avatarColumn.getStyleClass().addAll("avatar-column");
        avatarColumn.setCellValueFactory((offer) -> new ReadOnlyObjectWrapper<>(offer.getValue()));
        avatarColumn.setCellFactory(
                new Callback<>() {

                    @Override
                    public TableCell<OfferListItem, OfferListItem> call(TableColumn<OfferListItem, OfferListItem> column) {
                        return new TableCell<>() {
                            @Override
                            public void updateItem(final OfferListItem newItem, boolean empty) {
                                super.updateItem(newItem, empty);
                                if (newItem != null && !empty) {
                                    final Offer offer = newItem.offer;
                                    boolean myOffer = model.isMyOffer(offer);
                                    if (!myOffer) {
                                        final NodeAddress makersNodeAddress = offer.getOwnerNodeAddress();
                                        String role = Res.get("peerInfoIcon.tooltip.maker");
                                        PeerInfoIconSmall peerInfoIcon = new PeerInfoIconSmall(makersNodeAddress,
                                                role,
                                                offer,
                                                model.preferences,
                                                model.accountAgeWitnessService,
                                                useDevPrivilegeKeys);
//                                    setAlignment(Pos.CENTER);
                                        setGraphic(peerInfoIcon);
                                    } else {
                                        setGraphic(new Label(Res.get("shared.me")));
                                    }
                                } else {
                                    setGraphic(null);
                                }
                            }
                        };
                    }
                });

        tableView.getColumns().add(volumeColumn);
        tableView.getColumns().add(amountColumn);
        tableView.getColumns().add(priceColumn);
        tableView.getColumns().add(avatarColumn);

        tableView.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        Label placeholder = new AutoTooltipLabel(Res.get("table.placeholder.noItems", Res.get("shared.multipleOffers")));
        placeholder.setWrapText(true);
        tableView.setPlaceholder(placeholder);

        HBox titleButtonBox = new HBox();
        titleButtonBox.getStyleClass().add("offer-table-top");
        titleButtonBox.setAlignment(Pos.CENTER);

        Label titleLabel = new AutoTooltipLabel();
        titleLabel.getStyleClass().add("table-title");

        AutoTooltipButton button = new AutoTooltipButton();
        button.setContentDisplay(ContentDisplay.RIGHT);
        button.setGraphicTextGap(10);
        button.setMinHeight(32);

        Region spacer = new Region();

        HBox.setHgrow(spacer, Priority.ALWAYS);

        titleButtonBox.getChildren().addAll(titleLabel, spacer, button);

        VBox vBox = new VBox();
        VBox.setVgrow(tableView, Priority.ALWAYS);
        vBox.setPadding(new Insets(0, 0, 0, 0));
        vBox.setSpacing(0);
        vBox.setFillWidth(true);
        //vBox.setMinHeight(190);
        vBox.getChildren().addAll(titleButtonBox, tableView);

        return new Tuple4<>(tableView, vBox, button, titleLabel);
    }

    private void layout() {
        UserThread.runAfter(() -> {
            if (root.getScene() != null) {
                double newTableViewHeight = offerTableViewHeight.apply(root.getScene().getHeight());
                if (buyOfferTableView.getHeight() != newTableViewHeight) {
                    buyOfferTableView.setMinHeight(newTableViewHeight);
                    sellOfferTableView.setMinHeight(newTableViewHeight);
                }
            }
        }, 100, TimeUnit.MILLISECONDS);
    }
}
