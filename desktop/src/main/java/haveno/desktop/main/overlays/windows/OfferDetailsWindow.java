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

package haveno.desktop.main.overlays.windows;

import com.google.common.base.Joiner;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import haveno.common.UserThread;
import haveno.common.crypto.KeyRing;
import haveno.common.util.Tuple2;
import haveno.common.util.Tuple4;
import haveno.core.locale.CountryUtil;
import haveno.core.locale.Res;
import haveno.core.monetary.Price;
import haveno.core.offer.Offer;
import haveno.core.offer.OfferDirection;
import haveno.core.offer.OpenOffer;
import haveno.core.payment.PaymentAccount;
import haveno.core.payment.payload.PaymentMethod;
import haveno.core.trade.HavenoUtils;
import haveno.core.trade.Trade;
import haveno.core.trade.TradeManager;
import haveno.core.user.User;
import haveno.core.util.FormattingUtils;
import haveno.core.util.VolumeUtil;
import haveno.core.util.coin.CoinFormatter;
import haveno.desktop.Navigation;
import haveno.desktop.components.AutoTooltipButton;
import haveno.desktop.components.BusyAnimation;
import haveno.desktop.main.overlays.Overlay;
import haveno.desktop.main.overlays.editor.PasswordPopup;
import haveno.desktop.main.overlays.popups.Popup;
import haveno.desktop.util.CssTheme;
import haveno.desktop.util.DisplayUtils;
import static haveno.desktop.util.FormBuilder.addButtonAfterGroup;
import static haveno.desktop.util.FormBuilder.addButtonBusyAnimationLabelAfterGroup;
import static haveno.desktop.util.FormBuilder.addConfirmationLabelLabel;
import static haveno.desktop.util.FormBuilder.addConfirmationLabelTextArea;
import static haveno.desktop.util.FormBuilder.addConfirmationLabelTextFieldWithCopyIcon;
import static haveno.desktop.util.FormBuilder.addTitledGroupBg;
import haveno.desktop.util.GUIUtil;
import haveno.desktop.util.Layout;
import java.math.BigInteger;
import java.util.List;
import java.util.Optional;
import javafx.application.Platform;
import javafx.beans.binding.Bindings;
import javafx.geometry.HPos;
import javafx.geometry.Insets;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.control.Tooltip;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OfferDetailsWindow extends Overlay<OfferDetailsWindow> {
    protected static final Logger log = LoggerFactory.getLogger(OfferDetailsWindow.class);

    private final CoinFormatter formatter;
    private final User user;
    private final KeyRing keyRing;
    private final Navigation navigation;
    private Offer offer;
    private BigInteger tradeAmount;
    private Price tradePrice;
    private Optional<Runnable> placeOfferHandlerOptional = Optional.empty();
    private Optional<Runnable> takeOfferHandlerOptional = Optional.empty();
    private BusyAnimation busyAnimation;
    private TradeManager tradeManager;
    private Subscription numTradesSubscription;
    private Subscription initProgressSubscription;

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Public API
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Inject
    public OfferDetailsWindow(@Named(FormattingUtils.BTC_FORMATTER_KEY) CoinFormatter formatter,
                              User user,
                              KeyRing keyRing,
                              Navigation navigation,
                              TradeManager tradeManager) {
        this.formatter = formatter;
        this.user = user;
        this.keyRing = keyRing;
        this.navigation = navigation;
        this.tradeManager = tradeManager;
        type = Type.Confirmation;
    }

    public void show(Offer offer, BigInteger tradeAmount, Price tradePrice) {
        this.offer = offer;
        this.tradeAmount = tradeAmount;
        this.tradePrice = tradePrice;

        rowIndex = -1;
        width = 1118;
        createGridPane();
        addContent();
        display();
    }

    public void show(Offer offer) {
        this.offer = offer;
        rowIndex = -1;
        width = 1118;
        createGridPane();
        addContent();
        display();
    }

    public OfferDetailsWindow onPlaceOffer(Runnable placeOfferHandler) {
        this.placeOfferHandlerOptional = Optional.of(placeOfferHandler);
        return this;
    }

    public OfferDetailsWindow onTakeOffer(Runnable takeOfferHandler) {
        this.takeOfferHandlerOptional = Optional.of(takeOfferHandler);
        return this;
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Protected
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected void onHidden() {
        if (busyAnimation != null)
            busyAnimation.stop();

        if (numTradesSubscription != null) {
            numTradesSubscription.unsubscribe();
            numTradesSubscription = null;
        }

        if (initProgressSubscription != null) {
            initProgressSubscription.unsubscribe();
            initProgressSubscription = null;
        }
    }

    @Override
    protected void createGridPane() {
        super.createGridPane();
        gridPane.setPadding(new Insets(35, 40, 30, 40));
        gridPane.getStyleClass().add("grid-pane");
    }

    private void addContent() {
        gridPane.getColumnConstraints().get(0).setMinWidth(224);

        int rows = 5;
        List<String> acceptedBanks = offer.getAcceptedBankIds();
        boolean showAcceptedBanks = acceptedBanks != null && !acceptedBanks.isEmpty();
        List<String> acceptedCountryCodes = offer.getAcceptedCountryCodes();
        boolean showAcceptedCountryCodes = acceptedCountryCodes != null && !acceptedCountryCodes.isEmpty();
        boolean isF2F = offer.getPaymentMethod().equals(PaymentMethod.F2F);
        boolean showOfferExtraInfo = offer.getCombinedExtraInfo() != null && !offer.getCombinedExtraInfo().isEmpty();
        if (!takeOfferHandlerOptional.isPresent())
            rows++;
        if (showAcceptedBanks)
            rows++;
        if (showAcceptedCountryCodes)
            rows++;
        if (showOfferExtraInfo)
            rows++;
        if (isF2F)
            rows++;

        boolean showXmrAutoConf = offer.isXmr() && offer.getDirection() == OfferDirection.SELL;
        if (showXmrAutoConf) {
            rows++;
        }

        addTitledGroupBg(gridPane, ++rowIndex, rows, Res.get(offer.isPrivateOffer() ? "shared.Offer" : "shared.Offer"));

        String counterCurrencyDirectionInfo = "";
        String xmrDirectionInfo = "";
        OfferDirection direction = offer.getDirection();
        String currencyCode = offer.getCurrencyCode();
        String offerTypeLabel = Res.get("shared.offerType");
        String toReceive = " " + Res.get("shared.toReceive");
        String toSpend = " " + Res.get("shared.toSpend");
        double firstRowDistance = Layout.TWICE_FIRST_ROW_DISTANCE;
        if (takeOfferHandlerOptional.isPresent()) {
            addConfirmationLabelLabel(gridPane, rowIndex, offerTypeLabel,
                    DisplayUtils.getDirectionForTakeOffer(direction, currencyCode), firstRowDistance);
            counterCurrencyDirectionInfo = direction == OfferDirection.BUY ? toReceive : toSpend;
            xmrDirectionInfo = direction == OfferDirection.SELL ? toReceive : toSpend;
        } else if (placeOfferHandlerOptional.isPresent()) {
            addConfirmationLabelLabel(gridPane, rowIndex, offerTypeLabel,
                    DisplayUtils.getOfferDirectionForCreateOffer(direction, currencyCode, offer.isPrivateOffer()), firstRowDistance);
            counterCurrencyDirectionInfo = direction == OfferDirection.SELL ? toReceive : toSpend;
            xmrDirectionInfo = direction == OfferDirection.BUY ? toReceive : toSpend;
        } else {
            addConfirmationLabelLabel(gridPane, rowIndex, offerTypeLabel,
                    DisplayUtils.getDirectionBothSides(direction, offer.isPrivateOffer()), firstRowDistance);
        }
        String amount = Res.get("shared.xmrAmount");
        if (takeOfferHandlerOptional.isPresent()) {
            addConfirmationLabelLabel(gridPane, ++rowIndex, amount + xmrDirectionInfo,
                    HavenoUtils.formatXmr(tradeAmount, true));
            addConfirmationLabelLabel(gridPane, ++rowIndex, VolumeUtil.formatVolumeLabel(currencyCode) + counterCurrencyDirectionInfo,
                    VolumeUtil.formatVolumeWithCode(offer.getVolumeByAmount(tradeAmount)));
        } else {
            addConfirmationLabelLabel(gridPane, ++rowIndex, amount + xmrDirectionInfo,
                    HavenoUtils.formatXmr(offer.getAmount(), true));
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerDetailsWindow.minXmrAmount"),
                    HavenoUtils.formatXmr(offer.getMinAmount(), true));
            String volume = VolumeUtil.formatVolumeWithCode(offer.getVolume());
            String minVolume = "";
            if (offer.getVolume() != null && offer.getMinVolume() != null &&
                    !offer.getVolume().equals(offer.getMinVolume()))
                minVolume = " " + Res.get("offerDetailsWindow.min", VolumeUtil.formatVolumeWithCode(offer.getMinVolume()));
            addConfirmationLabelLabel(gridPane, ++rowIndex,
                    VolumeUtil.formatVolumeLabel(currencyCode) + counterCurrencyDirectionInfo, volume + minVolume);
        }

        String priceLabel = Res.get("shared.price");
        if (takeOfferHandlerOptional.isPresent()) {
            addConfirmationLabelLabel(gridPane, ++rowIndex, priceLabel, FormattingUtils.formatPrice(tradePrice));
        } else {
            Price price = offer.getPrice();
            if (offer.isUseMarketBasedPrice()) {
                addConfirmationLabelLabel(gridPane, ++rowIndex, priceLabel, FormattingUtils.formatPrice(price) +
                        " " + Res.get("offerDetailsWindow.distance",
                        FormattingUtils.formatPercentagePrice(offer.getMarketPriceMarginPct())));
            } else {
                addConfirmationLabelLabel(gridPane, ++rowIndex, priceLabel, FormattingUtils.formatPrice(price));
            }
        }
        final PaymentMethod paymentMethod = offer.getPaymentMethod();
        String bankId = offer.getBankId();
        if (bankId == null || bankId.equals("null"))
            bankId = "";
        else
            bankId = " (" + bankId + ")";
        final boolean isSpecificBanks = paymentMethod.equals(PaymentMethod.SPECIFIC_BANKS);
        final boolean isNationalBanks = paymentMethod.equals(PaymentMethod.NATIONAL_BANK);
        final boolean isSepa = paymentMethod.equals(PaymentMethod.SEPA);
        final String makerPaymentAccountId = offer.getMakerPaymentAccountId();
        final PaymentAccount myPaymentAccount = user.getPaymentAccount(makerPaymentAccountId);
        String countryCode = offer.getCountryCode();
        boolean isMyOffer = offer.isMyOffer(keyRing);
        if (isMyOffer && makerPaymentAccountId != null && myPaymentAccount != null) {
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerDetailsWindow.myTradingAccount"), myPaymentAccount.getAccountName());
        } else {
            final String method = Res.get(paymentMethod.getId());
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("shared.paymentMethod"), method);
        }

        if (showXmrAutoConf) {
            String isAutoConf = offer.isXmrAutoConf() ?
                    Res.get("shared.yes") :
                    Res.get("shared.no");
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerbook.xmrAutoConf"), isAutoConf);
        }

        if (showAcceptedBanks) {
            if (paymentMethod.equals(PaymentMethod.SAME_BANK)) {
                addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerDetailsWindow.bankId"), acceptedBanks.get(0));
            } else if (isSpecificBanks) {
                String value = Joiner.on(", ").join(acceptedBanks);
                String acceptedBanksLabel = Res.get("shared.acceptedBanks");
                Tooltip tooltip = new Tooltip(acceptedBanksLabel + " " + value);
                Label acceptedBanksTextField = addConfirmationLabelLabel(gridPane, ++rowIndex, acceptedBanksLabel, value).second;
                acceptedBanksTextField.setMouseTransparent(false);
                acceptedBanksTextField.setTooltip(tooltip);
            }
        }
        if (showAcceptedCountryCodes) {
            String countries;
            Tooltip tooltip = null;
            if (CountryUtil.containsAllSepaEuroCountries(acceptedCountryCodes)) {
                countries = Res.get("shared.allEuroCountries");
            } else {
                if (acceptedCountryCodes.size() == 1) {
                    countries = CountryUtil.getNameAndCode(acceptedCountryCodes.get(0));
                    tooltip = new Tooltip(countries);
                } else {
                    countries = CountryUtil.getCodesString(acceptedCountryCodes);
                    tooltip = new Tooltip(CountryUtil.getNamesByCodesString(acceptedCountryCodes));
                }
            }
            Label acceptedCountries = addConfirmationLabelLabel(gridPane, true, ++rowIndex,
                    Res.get("shared.acceptedTakerCountries"), countries).second;
            if (tooltip != null) {
                acceptedCountries.setMouseTransparent(false);
                acceptedCountries.setTooltip(tooltip);
            }
        }

        if (isF2F) {
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("payment.f2f.city"), offer.getF2FCity());
        }
        if (showOfferExtraInfo) {
            TextArea textArea = addConfirmationLabelTextArea(gridPane, ++rowIndex, Res.get("payment.shared.extraInfo"), "", 0).second;
            textArea.setText(offer.getCombinedExtraInfo());
            textArea.setMaxHeight(200);
            textArea.sceneProperty().addListener((o, oldScene, newScene) -> {
                if (newScene != null) {
                    // avoid javafx css warning
                    CssTheme.loadSceneStyles(newScene, CssTheme.CSS_THEME_LIGHT, false);
                    textArea.applyCss();
                    var text = textArea.lookup(".text");

                    textArea.prefHeightProperty().bind(Bindings.createDoubleBinding(() -> {
                        return textArea.getFont().getSize() + text.getBoundsInLocal().getHeight();
                    }, text.boundsInLocalProperty()));

                    text.boundsInLocalProperty().addListener((observableBoundsAfter, boundsBefore, boundsAfter) -> {
                        Platform.runLater(() -> textArea.requestLayout());
                    });
                }
            });
            textArea.setEditable(false);
        }

        // get amount reserved for the offer
        BigInteger reservedAmount = isMyOffer ? offer.getReservedAmount() : null;

        // get offer challenge
        OpenOffer myOpenOffer = HavenoUtils.openOfferManager.getOpenOffer(offer.getId()).orElse(null);
        String offerChallenge = myOpenOffer == null ? null : myOpenOffer.getChallenge();

        rows = 3;
        if (countryCode != null)
            rows++;
        if (!isF2F)
            rows++;
        if (reservedAmount != null)
            rows++;
        if (offerChallenge != null)
            rows++;

        addTitledGroupBg(gridPane, ++rowIndex, rows, Res.get("shared.details"), Layout.GROUP_DISTANCE);
        addConfirmationLabelTextFieldWithCopyIcon(gridPane, rowIndex, Res.get("shared.offerId"), offer.getId(),
                Layout.TWICE_FIRST_ROW_AND_GROUP_DISTANCE);
        addConfirmationLabelTextFieldWithCopyIcon(gridPane, ++rowIndex, Res.get("offerDetailsWindow.makersOnion"),
                offer.getMakerNodeAddress().getFullAddress());
        addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerDetailsWindow.creationDate"),
                DisplayUtils.formatDateTime(offer.getDate()));
        String value = Res.getWithColAndCap("shared.buyer") +
                " " +
                HavenoUtils.formatXmr(takeOfferHandlerOptional.isPresent() ? offer.getOfferPayload().getBuyerSecurityDepositForTradeAmount(tradeAmount) : offer.getOfferPayload().getMaxBuyerSecurityDeposit(), true) +
                " / " +
                Res.getWithColAndCap("shared.seller") +
                " " +
                HavenoUtils.formatXmr(takeOfferHandlerOptional.isPresent() ? offer.getOfferPayload().getSellerSecurityDepositForTradeAmount(tradeAmount) : offer.getOfferPayload().getMaxSellerSecurityDeposit(), true);
        addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("shared.securityDeposit"), value);

        if (reservedAmount != null) {
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("shared.reservedAmount"),  HavenoUtils.formatXmr(reservedAmount, true));
        }

        if (countryCode != null && !isF2F)
            addConfirmationLabelLabel(gridPane, ++rowIndex, Res.get("offerDetailsWindow.countryBank"),
                    CountryUtil.getNameAndCode(countryCode));

        if (offerChallenge != null)
            addConfirmationLabelTextFieldWithCopyIcon(gridPane, ++rowIndex, Res.get("offerDetailsWindow.challenge"), offerChallenge);

        if (placeOfferHandlerOptional.isPresent()) {
            addTitledGroupBg(gridPane, ++rowIndex, 1, Res.get("offerDetailsWindow.commitment"), Layout.GROUP_DISTANCE);
            final Tuple2<Label, Label> labelLabelTuple2 = addConfirmationLabelLabel(gridPane, rowIndex, Res.get("offerDetailsWindow.agree"), Res.get("createOffer.tac"),
                    Layout.TWICE_FIRST_ROW_AND_GROUP_DISTANCE);
            labelLabelTuple2.second.setWrapText(true);

            addConfirmAndCancelButtons(true);
        } else if (takeOfferHandlerOptional.isPresent()) {
            addTitledGroupBg(gridPane, ++rowIndex, 1, Res.get("shared.contract"), Layout.GROUP_DISTANCE);
            final Tuple2<Label, Label> labelLabelTuple2 = addConfirmationLabelLabel(gridPane, rowIndex, Res.get("offerDetailsWindow.tac"), Res.get("takeOffer.tac"),
                    Layout.TWICE_FIRST_ROW_AND_GROUP_DISTANCE);
            labelLabelTuple2.second.setWrapText(true);

            addConfirmAndCancelButtons(false);
        } else {
            Button closeButton = addButtonAfterGroup(gridPane, ++rowIndex, Res.get("shared.close"));
            GridPane.setColumnIndex(closeButton, 1);
            GridPane.setHalignment(closeButton, HPos.RIGHT);

            closeButton.setOnAction(e -> {
                closeHandlerOptional.ifPresent(Runnable::run);
                hide();
            });
        }
    }

    private void addConfirmAndCancelButtons(boolean isPlaceOffer) {
        boolean isBuyOffer = offer.isBuyOffer();
        boolean isBuyerRole = isPlaceOffer == isBuyOffer;
        String placeOfferButtonText = isBuyerRole ?
                Res.get("offerDetailsWindow.confirm.maker", Res.get("shared.buy")) :
                Res.get("offerDetailsWindow.confirm.maker", Res.get("shared.sell"));
        String takeOfferButtonText = isBuyerRole ?
                Res.get("offerDetailsWindow.confirm.taker", Res.get("shared.buy")) :
                Res.get("offerDetailsWindow.confirm.taker", Res.get("shared.sell"));

        ImageView iconView = new ImageView();
        iconView.setId(isBuyerRole ? "image-buy-white" : "image-sell-white");

        Tuple4<Button, BusyAnimation, Label, HBox> placeOfferTuple = addButtonBusyAnimationLabelAfterGroup(gridPane,
                ++rowIndex, 1,
                isPlaceOffer ? placeOfferButtonText : takeOfferButtonText);

        AutoTooltipButton confirmButton = (AutoTooltipButton) placeOfferTuple.first;
        confirmButton.setMinHeight(40);
        confirmButton.setPadding(new Insets(0, 20, 0, 20));
        confirmButton.setGraphic(iconView);
        confirmButton.setGraphicTextGap(10);
        confirmButton.setId(isBuyerRole ? "buy-button-big" : "sell-button-big");
        confirmButton.updateText(isPlaceOffer ? placeOfferButtonText : takeOfferButtonText);

        busyAnimation = placeOfferTuple.second;
        Label spinnerInfoLabel = placeOfferTuple.third;

        Button cancelButton = new AutoTooltipButton(Res.get("shared.cancel"));
        cancelButton.setDefaultButton(false);
        cancelButton.setOnAction(e -> {
            closeHandlerOptional.ifPresent(Runnable::run);
            hide();
        });

        placeOfferTuple.fourth.getChildren().add(cancelButton);

        confirmButton.setOnAction(e -> {
            if (GUIUtil.canCreateOrTakeOfferOrShowPopup(user, navigation)) {
                if (!isPlaceOffer && offer.isPrivateOffer()) {
                    new PasswordPopup()
                            .headLine(Res.get("offerbook.takeOffer.enterChallenge"))
                            .onAction(password -> {
                                if (offer.getChallengeHash().equals(HavenoUtils.getChallengeHash(password))) {
                                    offer.setChallenge(password);
                                    confirmTakeOfferAux(confirmButton, cancelButton, spinnerInfoLabel, isPlaceOffer);
                                } else {
                                    new Popup().warning(Res.get("password.wrongPw")).show();
                                }
                            })
                            .closeButtonText(Res.get("shared.cancel"))
                            .show();
                } else {
                    confirmTakeOfferAux(confirmButton, cancelButton, spinnerInfoLabel, isPlaceOffer);
                }
            }
        });
    }

    private void confirmTakeOfferAux(Button button, Button cancelButton, Label spinnerInfoLabel, boolean isPlaceOffer) {
        button.setDisable(true);
        cancelButton.setDisable(isPlaceOffer ? false : true); // TODO: enable cancel button for taking an offer until messages sent
        // temporarily disabled due to high CPU usage (per issue #4649)
        // busyAnimation.play();
        if (isPlaceOffer) {
            spinnerInfoLabel.setText(Res.get("createOffer.fundsBox.placeOfferSpinnerInfo"));
            placeOfferHandlerOptional.ifPresent(Runnable::run);
        } else {

            // subscribe to trade progress
            spinnerInfoLabel.setText(Res.get("takeOffer.fundsBox.takeOfferSpinnerInfo", "0%"));
            numTradesSubscription = EasyBind.subscribe(tradeManager.getNumPendingTrades(), newNum -> {
                subscribeToProgress(spinnerInfoLabel);
            });

            takeOfferHandlerOptional.ifPresent(Runnable::run);
        }
    }

    private void subscribeToProgress(Label spinnerInfoLabel) {
        Trade trade = tradeManager.getTrade(offer.getId());
        if (trade == null || initProgressSubscription != null) return;
        initProgressSubscription = EasyBind.subscribe(trade.initProgressProperty(), newProgress -> {
            String progress = (int) (newProgress.doubleValue() * 100.0) + "%";
            UserThread.execute(() -> spinnerInfoLabel.setText(Res.get("takeOffer.fundsBox.takeOfferSpinnerInfo", progress)));
        });
    }
}
