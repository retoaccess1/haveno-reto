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

package haveno.desktop.main.portfolio.pendingtrades.steps;

import static com.google.common.base.Preconditions.checkNotNull;
import de.jensd.fx.fontawesome.AwesomeDude;
import de.jensd.fx.fontawesome.AwesomeIcon;
import haveno.common.ClockWatcher;
import haveno.common.UserThread;
import haveno.common.util.Tuple3;
import haveno.core.locale.CurrencyUtil;
import haveno.core.locale.Res;
import haveno.core.support.dispute.Dispute;
import haveno.core.support.dispute.DisputeResult;
import haveno.core.support.dispute.mediation.MediationResultState;
import haveno.core.trade.ArbitratorTrade;
import haveno.core.trade.Contract;
import haveno.core.trade.HavenoUtils;
import haveno.core.trade.MakerTrade;
import haveno.core.trade.TakerTrade;
import haveno.core.trade.Trade;
import haveno.core.user.DontShowAgainLookup;
import haveno.core.user.Preferences;
import haveno.desktop.components.InfoTextField;
import haveno.desktop.components.TitledGroupBg;
import haveno.desktop.components.TxIdTextField;
import static haveno.desktop.components.paymentmethods.PaymentMethodForm.addOpenTradeDuration;
import haveno.desktop.main.overlays.popups.Popup;
import haveno.desktop.main.portfolio.pendingtrades.PendingTradesViewModel;
import haveno.desktop.main.portfolio.pendingtrades.TradeStepInfo;
import haveno.desktop.main.portfolio.pendingtrades.TradeSubView;
import static haveno.desktop.util.FormBuilder.addCompactTopLabelTextField;
import static haveno.desktop.util.FormBuilder.addMultilineLabel;
import static haveno.desktop.util.FormBuilder.addTitledGroupBg;
import static haveno.desktop.util.FormBuilder.addTopLabelTxIdTextField;
import haveno.desktop.util.Layout;
import haveno.network.p2p.BootstrapListener;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import javafx.application.Platform;
import javafx.beans.property.BooleanProperty;
import javafx.beans.value.ChangeListener;
import javafx.geometry.Insets;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ScrollPane;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import org.fxmisc.easybind.EasyBind;
import org.fxmisc.easybind.Subscription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TradeStepView extends AnchorPane {
    protected final Logger log = LoggerFactory.getLogger(this.getClass());

    protected final PendingTradesViewModel model;
    protected final Trade trade;
    protected final Preferences preferences;
    protected final GridPane gridPane;

    private Subscription tradePeriodStateSubscription, disputeStateSubscription, mediationResultStateSubscription;
    protected int gridRow = 0;
    private TextField timeLeftTextField;
    private ProgressBar timeLeftProgressBar;
    private TxIdTextField selfTxIdTextField;
    private TxIdTextField peerTxIdTextField;
    private TradeStepInfo tradeStepInfo;
    private Subscription selfTxIdSubscription;
    private Subscription peerTxIdSubscription;
    private ClockWatcher.Listener clockListener;
    private final ChangeListener<String> errorMessageListener;
    protected Label infoLabel;
    private Popup acceptMediationResultPopup;
    private BootstrapListener bootstrapListener;
    private TradeSubView.ChatCallback chatCallback;
    private ChangeListener<Boolean> pendingTradesInitializedListener;


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor, Initialisation
    ///////////////////////////////////////////////////////////////////////////////////////////

    protected TradeStepView(PendingTradesViewModel model) {
        this.model = model;
        preferences = model.dataModel.preferences;
        trade = model.dataModel.getTrade();
        checkNotNull(trade, "Trade must not be null at TradeStepView");

        ScrollPane scrollPane = new ScrollPane();
        scrollPane.setHbarPolicy(ScrollPane.ScrollBarPolicy.NEVER);
        scrollPane.setVbarPolicy(ScrollPane.ScrollBarPolicy.AS_NEEDED);
        scrollPane.setFitToHeight(true);
        scrollPane.setFitToWidth(true);

        AnchorPane.setLeftAnchor(scrollPane, 10d);
        AnchorPane.setRightAnchor(scrollPane, 10d);
        AnchorPane.setTopAnchor(scrollPane, 10d);
        AnchorPane.setBottomAnchor(scrollPane, 0d);

        getChildren().add(scrollPane);

        gridPane = new GridPane();

        gridPane.setHgap(Layout.GRID_GAP);
        gridPane.setVgap(Layout.GRID_GAP);
        gridPane.setPadding(new Insets(0, 0, 25, 0));
        ColumnConstraints columnConstraints1 = new ColumnConstraints();
        columnConstraints1.setHgrow(Priority.ALWAYS);

        ColumnConstraints columnConstraints2 = new ColumnConstraints();
        columnConstraints2.setHgrow(Priority.ALWAYS);

        gridPane.getColumnConstraints().addAll(columnConstraints1, columnConstraints2);

        scrollPane.setContent(gridPane);

        AnchorPane.setLeftAnchor(this, 0d);
        AnchorPane.setRightAnchor(this, 0d);
        AnchorPane.setTopAnchor(this, -10d);
        AnchorPane.setBottomAnchor(this, 0d);

        addContent();

        errorMessageListener = (observable, oldValue, newValue) -> {
            if (newValue != null)
                new Popup().error(newValue).show();
        };

        clockListener = new ClockWatcher.Listener() {
            @Override
            public void onSecondTick() {
            }

            @Override
            public void onMinuteTick() {
                updateTimeLeft();
            }
        };

//        newBestBlockListener = block -> {
//            checkIfLockTimeIsOver();
//        };
    }

    public void activate() {
        if (selfTxIdTextField != null) {
            if (selfTxIdSubscription != null)
                selfTxIdSubscription.unsubscribe();

            selfTxIdSubscription = EasyBind.subscribe(model.dataModel.isMaker() ? model.dataModel.makerTxId : model.dataModel.takerTxId, id -> {
                if (!id.isEmpty()) {
                    selfTxIdTextField.setup(id, trade);
                } else {
                    selfTxIdTextField.cleanup();
                }
            });
        }
        if (peerTxIdTextField != null) {
            if (peerTxIdSubscription != null)
                peerTxIdSubscription.unsubscribe();

            peerTxIdSubscription = EasyBind.subscribe(model.dataModel.isMaker() ? model.dataModel.takerTxId : model.dataModel.makerTxId, id -> {
                if (!id.isEmpty()) {
                    peerTxIdTextField.setup(id, trade);
                } else {
                    peerTxIdTextField.cleanup();
                }
            });
        }
        trade.errorMessageProperty().addListener(errorMessageListener);

        tradeStepInfo.setOnAction(e -> {
            if (!isArbitrationOpenedState() && this.isTradePeriodOver()) {
                openSupportTicket();
            } else {
                openChat();
            }
        });

        // We get mailbox messages processed after we have bootstrapped. This will influence the states we
        // handle in our disputeStateSubscription and mediationResultStateSubscriptions. To avoid that we show
        // popups from incorrect states we wait until we have bootstrapped and the mailbox messages processed.
        if (model.p2PService.isBootstrapped()) {
            registerSubscriptions();
        } else {
            bootstrapListener = new BootstrapListener() {
                @Override
                public void onDataReceived() {
                    registerSubscriptions();
                }
            };
            model.p2PService.addP2PServiceListener(bootstrapListener);
        }

        tradePeriodStateSubscription = EasyBind.subscribe(trade.tradePeriodStateProperty(), newValue -> {
            if (newValue != null) {
                UserThread.execute(() -> updateTradePeriodState(newValue));
            }
        });

        model.clockWatcher.addListener(clockListener);

        if (infoLabel != null) {
            infoLabel.setText(getInfoText());
        }

        BooleanProperty initialized = model.dataModel.tradeManager.getPersistedTradesInitialized();
        if (initialized.get()) {
            onPendingTradesInitialized();
        } else {
            pendingTradesInitializedListener = (observable, oldValue, newValue) -> {
                if (newValue) {
                    onPendingTradesInitialized();
                    UserThread.execute(() -> initialized.removeListener(pendingTradesInitializedListener));
                }
            };
            initialized.addListener(pendingTradesInitializedListener);
        }
    }

    protected void onPendingTradesInitialized() {
//        model.dataModel.xmrWalletService.addNewBestBlockListener(newBestBlockListener); // TODO (woodser): different listener?
//        checkIfLockTimeIsOver();
    }

    private void registerSubscriptions() {
        disputeStateSubscription = EasyBind.subscribe(trade.disputeStateProperty(), newValue -> {
            if (newValue != null) {
                updateDisputeState(newValue);
            }
        });

        mediationResultStateSubscription = EasyBind.subscribe(trade.mediationResultStateProperty(), newValue -> {
            if (newValue != null) {
                updateMediationResultState(true);
            }
        });

        UserThread.execute(() -> model.p2PService.removeP2PServiceListener(bootstrapListener));
    }

    private void openSupportTicket() {
        if (trade.getPhase().ordinal() < Trade.Phase.DEPOSITS_UNLOCKED.ordinal()) {
            new Popup().warning(Res.get("portfolio.pending.error.depositTxNotConfirmed")).show();
        } else {
            applyOnDisputeOpened();
            model.dataModel.onOpenDispute();
        }
    }

    private void openChat() {
        // call up the chain to open chat
        if (this.chatCallback != null) {
            this.chatCallback.onOpenChat(this.trade);
        }
    }

    public void deactivate() {
      if (selfTxIdSubscription != null)
          selfTxIdSubscription.unsubscribe();
      if (peerTxIdSubscription != null)
          peerTxIdSubscription.unsubscribe();

      if (selfTxIdTextField != null)
          selfTxIdTextField.cleanup();
      if (peerTxIdTextField != null)
          peerTxIdTextField.cleanup();

      if (errorMessageListener != null)
          trade.errorMessageProperty().removeListener(errorMessageListener);

      if (disputeStateSubscription != null)
          disputeStateSubscription.unsubscribe();

      if (mediationResultStateSubscription != null)
          mediationResultStateSubscription.unsubscribe();

      if (tradePeriodStateSubscription != null)
          tradePeriodStateSubscription.unsubscribe();

      if (clockListener != null)
          model.clockWatcher.removeListener(clockListener);

      if (tradeStepInfo != null)
          tradeStepInfo.setOnAction(null);

      if (acceptMediationResultPopup != null) {
          acceptMediationResultPopup.hide();
          acceptMediationResultPopup = null;
      }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Content
    ///////////////////////////////////////////////////////////////////////////////////////////

    protected void addContent() {
        addTradeInfoBlock();
        addInfoBlock();
    }

    protected void addTradeInfoBlock() {
        TitledGroupBg tradeInfoTitledGroupBg = addTitledGroupBg(gridPane, gridRow, 3,
                Res.get("portfolio.pending.tradeInformation"));
        GridPane.setColumnSpan(tradeInfoTitledGroupBg, 2);

        // self's deposit tx id
        boolean showSelfTxId = model.dataModel.isMaker() || !trade.hasBuyerAsTakerWithoutDeposit();
        if (showSelfTxId) {
            final Tuple3<Label, TxIdTextField, VBox> labelSelfTxIdTextFieldVBoxTuple3 =
            addTopLabelTxIdTextField(gridPane, gridRow, Res.get("shared.yourDepositTransactionId"),
                    Layout.COMPACT_FIRST_ROW_DISTANCE);

            GridPane.setColumnSpan(labelSelfTxIdTextFieldVBoxTuple3.third, 2);
            selfTxIdTextField = labelSelfTxIdTextFieldVBoxTuple3.second;

            String selfTxId = model.dataModel.isMaker() ? model.dataModel.makerTxId.get() : model.dataModel.takerTxId.get();
            if (!selfTxId.isEmpty())
                selfTxIdTextField.setup(selfTxId, trade);
            else
                selfTxIdTextField.cleanup();
        }

        // peer's deposit tx id
        boolean showPeerTxId = !model.dataModel.isMaker() || !trade.hasBuyerAsTakerWithoutDeposit();
        if (showPeerTxId) {
            final Tuple3<Label, TxIdTextField, VBox> labelPeerTxIdTextFieldVBoxTuple3 =
            addTopLabelTxIdTextField(gridPane, showSelfTxId ? ++gridRow : gridRow, Res.get("shared.peerDepositTransactionId"),
                    showSelfTxId ? -Layout.GROUP_DISTANCE_WITHOUT_SEPARATOR : Layout.COMPACT_FIRST_ROW_DISTANCE);

            GridPane.setColumnSpan(labelPeerTxIdTextFieldVBoxTuple3.third, 2);
            peerTxIdTextField = labelPeerTxIdTextFieldVBoxTuple3.second;

            String peerTxId = model.dataModel.isMaker() ? model.dataModel.takerTxId.get() : model.dataModel.makerTxId.get();
            if (!peerTxId.isEmpty())
                peerTxIdTextField.setup(peerTxId, trade);
            else
                peerTxIdTextField.cleanup();
        }

        if (model.dataModel.getTrade() != null) {
            checkNotNull(model.dataModel.getTrade().getOffer(), "Offer must not be null in TradeStepView");
            InfoTextField infoTextField = addOpenTradeDuration(gridPane, ++gridRow,
                    model.dataModel.getTrade().getOffer());
            infoTextField.setContentForInfoPopOver(createInfoPopover());
        }

        final Tuple3<Label, TextField, VBox> labelTextFieldVBoxTuple3 = addCompactTopLabelTextField(gridPane, gridRow,
                1, Res.get("portfolio.pending.remainingTime"), "");

        timeLeftTextField = labelTextFieldVBoxTuple3.second;
        timeLeftTextField.setMinWidth(400);

        timeLeftProgressBar = new ProgressBar(0);
        timeLeftProgressBar.setOpacity(0.7);
        timeLeftProgressBar.setMinHeight(9);
        timeLeftProgressBar.setMaxHeight(9);
        timeLeftProgressBar.setMaxWidth(Double.MAX_VALUE);

        GridPane.setRowIndex(timeLeftProgressBar, ++gridRow);
        GridPane.setColumnSpan(timeLeftProgressBar, 2);
        GridPane.setFillWidth(timeLeftProgressBar, true);
        gridPane.getChildren().add(timeLeftProgressBar);

        updateTimeLeft();
    }

    protected void addInfoBlock() {
        final TitledGroupBg titledGroupBg = addTitledGroupBg(gridPane, ++gridRow, 1, getInfoBlockTitle(),
                Layout.COMPACT_GROUP_DISTANCE);
        titledGroupBg.getStyleClass().add("last");
        GridPane.setColumnSpan(titledGroupBg, 2);

        infoLabel = addMultilineLabel(gridPane, gridRow, "", Layout.COMPACT_FIRST_ROW_AND_COMPACT_GROUP_DISTANCE);
        GridPane.setColumnSpan(infoLabel, 2);
    }

    protected String getInfoText() {
        return "";
    }

    protected String getInfoBlockTitle() {
        return "";
    }

    private void updateTimeLeft() {
        if (!trade.isInitialized()) return;
        if (timeLeftTextField != null) {

            // TODO (woodser): extra TradeStepView created but not deactivated on trade.setState(), so deactivate when model's trade is null
            if (model.dataModel.getTrade() == null) {
                log.warn("deactivating TradeStepView because model's trade is null");

                // schedule deactivation to avoid concurrent modification of clock listeners
                Platform.runLater(() -> deactivate());
                return;
            }

            String remainingTime = model.getRemainingTradeDurationAsWords();
            timeLeftProgressBar.setProgress(model.getRemainingTradeDurationAsPercentage());
            if (!remainingTime.isEmpty()) {
                timeLeftTextField.setText(Res.get("portfolio.pending.remainingTimeDetail",
                        remainingTime, model.getDateForOpenDispute()));
                if (model.showWarning() || model.showDispute()) {
                    timeLeftTextField.getStyleClass().add("error-text");
                    timeLeftProgressBar.getStyleClass().add("error");
                }
            } else {
                timeLeftTextField.setText(Res.get("portfolio.pending.tradeNotCompleted",
                        model.getDateForOpenDispute()));
                timeLeftTextField.getStyleClass().add("error-text");
                timeLeftProgressBar.getStyleClass().add("error");
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Dispute/warning label and button
    ///////////////////////////////////////////////////////////////////////////////////////////

    // We have the dispute button and text field on the left side, but we handle the content here as it
    // is trade state specific
    public void setTradeStepInfo(TradeStepInfo tradeStepInfo) {
        this.tradeStepInfo = tradeStepInfo;

        tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
        tradeStepInfo.setPeriodOverWarnTextSupplier(this::getPeriodOverWarnText);
    }

    protected void hideTradeStepInfo() {
        tradeStepInfo.setState(TradeStepInfo.State.TRADE_COMPLETED);
    }

    protected String getFirstHalfOverWarnText() {
        return "";
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Dispute
    ///////////////////////////////////////////////////////////////////////////////////////////

    protected String getPeriodOverWarnText() {
        return "";
    }

    protected void applyOnDisputeOpened() {
    }

    protected void updateDisputeState(Trade.DisputeState disputeState) {
        Optional<Dispute> ownDispute;
        switch (disputeState) {
            case NO_DISPUTE:
                break;

            case DISPUTE_REQUESTED:
            case DISPUTE_OPENED:
                if (tradeStepInfo != null) {
                    tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
                }
                applyOnDisputeOpened();

                // update trade view unless arbitrator
                if (trade instanceof ArbitratorTrade) break;
                ownDispute = model.dataModel.arbitrationManager.findDispute(trade.getId());
                ownDispute.ifPresent(dispute -> {
                    if (tradeStepInfo != null) {
                        boolean isOpener = dispute.isDisputeOpenerIsBuyer() ? trade.isBuyer() : trade.isSeller();
                        tradeStepInfo.setState(isOpener ? TradeStepInfo.State.IN_ARBITRATION_SELF_REQUESTED : TradeStepInfo.State.IN_ARBITRATION_PEER_REQUESTED);
                    }
                });
                break;

            case DISPUTE_CLOSED:
                break;
            case MEDIATION_REQUESTED:
                if (tradeStepInfo != null) {
                    tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
                }
                applyOnDisputeOpened();

                ownDispute = model.dataModel.mediationManager.findDispute(trade.getId());
                ownDispute.ifPresent(dispute -> {
                    if (tradeStepInfo != null)
                        tradeStepInfo.setState(TradeStepInfo.State.IN_MEDIATION_SELF_REQUESTED);
                });
                break;
            case MEDIATION_STARTED_BY_PEER:
                if (tradeStepInfo != null) {
                    tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
                }
                applyOnDisputeOpened();

                ownDispute = model.dataModel.mediationManager.findDispute(trade.getId());
                ownDispute.ifPresent(dispute -> {
                    if (tradeStepInfo != null) {
                        tradeStepInfo.setState(TradeStepInfo.State.IN_MEDIATION_PEER_REQUESTED);
                    }
                });
                break;
            case MEDIATION_CLOSED:
              if (tradeStepInfo != null) {
                tradeStepInfo.setOnAction(e -> {
                    updateMediationResultState(false);
                });
              }

              if (tradeStepInfo != null) {
                tradeStepInfo.setState(TradeStepInfo.State.MEDIATION_RESULT);
              }

              updateMediationResultState(true);
              break;
            case REFUND_REQUESTED:
                  throw new RuntimeException("Unhandled case: " + Trade.DisputeState.REFUND_REQUESTED);
//                if (tradeStepInfo != null) {
//                    tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
//                }
//                applyOnDisputeOpened();
//
//                ownDispute = model.dataModel.refundManager.findOwnDispute(trade.getId());
//                ownDispute.ifPresent(dispute -> {
//                    if (tradeStepInfo != null)
//                        tradeStepInfo.setState(TradeStepInfo.State.IN_REFUND_REQUEST_SELF_REQUESTED);
//                });
//
//                if (acceptMediationResultPopup != null) {
//                    acceptMediationResultPopup.hide();
//                    acceptMediationResultPopup = null;
//                }
//
//                break;
            case REFUND_REQUEST_STARTED_BY_PEER:
                throw new RuntimeException("Unhandled case: " + Trade.DisputeState.REFUND_REQUEST_STARTED_BY_PEER);
//                if (tradeStepInfo != null) {
//                    tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
//                }
//                applyOnDisputeOpened();
//
//                ownDispute = model.dataModel.refundManager.findOwnDispute(trade.getId());
//                ownDispute.ifPresent(dispute -> {
//                    if (tradeStepInfo != null)
//                        tradeStepInfo.setState(TradeStepInfo.State.IN_REFUND_REQUEST_PEER_REQUESTED);
//                });
//
//                if (acceptMediationResultPopup != null) {
//                    acceptMediationResultPopup.hide();
//                    acceptMediationResultPopup = null;
//                }
//                break;
            case REFUND_REQUEST_CLOSED:
                break;
            default:
                break;
        }
    }

    private void updateMediationResultState(boolean blockOpeningOfResultAcceptedPopup) {
        if (isInMediation()) {
            if (isRefundRequestStartedByPeer()) {
                tradeStepInfo.setState(TradeStepInfo.State.IN_REFUND_REQUEST_PEER_REQUESTED);
            } else if (isRefundRequestSelfStarted()) {
                tradeStepInfo.setState(TradeStepInfo.State.IN_REFUND_REQUEST_SELF_REQUESTED);
            }
        } else if (isMediationClosedState()) {
            // We do not use the state itself as it is not guaranteed the last state reflects relevant information
            // (e.g. we might receive a RECEIVED_SIG_MSG but then later a SIG_MSG_IN_MAILBOX).
            if (hasSelfAccepted()) {
                tradeStepInfo.setState(TradeStepInfo.State.MEDIATION_RESULT_SELF_ACCEPTED);
                if (!blockOpeningOfResultAcceptedPopup)
                    openMediationResultPopup(Res.get("portfolio.pending.mediationResult.popup.headline", trade.getShortId()));
            } else if (peerAccepted()) {
                tradeStepInfo.setState(TradeStepInfo.State.MEDIATION_RESULT_PEER_ACCEPTED);
                if (acceptMediationResultPopup == null) {
                    openMediationResultPopup(Res.get("portfolio.pending.mediationResult.popup.headline.peerAccepted", trade.getShortId()));
                }
            } else {
                tradeStepInfo.setState(TradeStepInfo.State.MEDIATION_RESULT);
                openMediationResultPopup(Res.get("portfolio.pending.mediationResult.popup.headline", trade.getShortId()));
            }
        }
    }

    private boolean isInMediation() {
        return isRefundRequestStartedByPeer() || isRefundRequestSelfStarted();
    }

    private boolean isRefundRequestStartedByPeer() {
        return trade.getDisputeState() == Trade.DisputeState.REFUND_REQUEST_STARTED_BY_PEER;
    }

    private boolean isRefundRequestSelfStarted() {
        return trade.getDisputeState() == Trade.DisputeState.REFUND_REQUESTED;
    }

    private boolean isMediationClosedState() {
        return trade.getDisputeState() == Trade.DisputeState.MEDIATION_CLOSED;
    }

    private boolean isArbitrationOpenedState() {
        return trade.getDisputeState().isOpen();
    }

    private boolean isTradePeriodOver() {
        return Trade.TradePeriodState.TRADE_PERIOD_OVER == trade.tradePeriodStateProperty().get();
    }

    private boolean hasSelfAccepted() {
        return trade.getProcessModel().getMediatedPayoutTxSignature() != null;
    }

    private boolean peerAccepted() {
        return trade.getTradePeer().getMediatedPayoutTxSignature() != null;
    }

    private void openMediationResultPopup(String headLine) {
        if (acceptMediationResultPopup != null) {
            return;
        }

        Optional<Dispute> optionalDispute = model.dataModel.mediationManager.findDispute(trade.getId());
        if (optionalDispute.isEmpty()) {
            return;
        }

        if (trade.getPayoutTxId() != null) {
            return;
        }

        if (trade instanceof MakerTrade && trade.getMakerDepositTx() == null) {
          log.error("trade.getMakerDepositTx() was null at openMediationResultPopup. " +
                  "We add the trade to failed trades. TradeId={}", trade.getId());
          //model.dataModel.addTradeToFailedTrades(); // TODO (woodser): new way to move trade to failed trades?
          model.dataModel.onMoveInvalidTradeToFailedTrades(trade);
          new Popup().warning(Res.get("portfolio.pending.mediationResult.error.depositTxNull")).show(); // TODO (woodser): separate error messages for maker/taker
          return;
        } else if (trade instanceof TakerTrade && trade.getTakerDepositTx() == null && !trade.hasBuyerAsTakerWithoutDeposit()) {
          log.error("trade.getTakerDepositTx() was null at openMediationResultPopup. " +
                  "We add the trade to failed trades. TradeId={}", trade.getId());
          //model.dataModel.addTradeToFailedTrades();
          model.dataModel.onMoveInvalidTradeToFailedTrades(trade);
          new Popup().warning(Res.get("portfolio.pending.mediationResult.error.depositTxNull")).show();
          return;
        }

        DisputeResult disputeResult = optionalDispute.get().getDisputeResultProperty().get();
        Contract contract = checkNotNull(trade.getContract(), "contract must not be null");
        boolean isMyRoleBuyer = contract.isMyRoleBuyer(model.dataModel.getPubKeyRingProvider().get());
        String buyerPayoutAmount = HavenoUtils.formatXmr(disputeResult.getBuyerPayoutAmountBeforeCost(), true);
        String sellerPayoutAmount = HavenoUtils.formatXmr(disputeResult.getSellerPayoutAmountBeforeCost(), true);
        String myPayoutAmount = isMyRoleBuyer ? buyerPayoutAmount : sellerPayoutAmount;
        String peersPayoutAmount = isMyRoleBuyer ? sellerPayoutAmount : buyerPayoutAmount;

        String actionButtonText = hasSelfAccepted() ?
                Res.get("portfolio.pending.mediationResult.popup.alreadyAccepted") : Res.get("shared.accept");

        String message;
        MediationResultState mediationResultState = checkNotNull(trade).getMediationResultState();
        if (mediationResultState == null) {
            return;
        }

        switch (mediationResultState) {
            case MEDIATION_RESULT_ACCEPTED:
            case SIG_MSG_SENT:
            case SIG_MSG_ARRIVED:
            case SIG_MSG_IN_MAILBOX:
            case SIG_MSG_SEND_FAILED:
                message = Res.get("portfolio.pending.mediationResult.popup.selfAccepted.lockTimeOver",
                        "N/A",  // TODO (woodser): no timelocked tx in xmr, so part of popup message is n/a
                        -1);
                break;
            default:
                message = Res.get("portfolio.pending.mediationResult.popup.info",
                        myPayoutAmount,
                        peersPayoutAmount,
                        "N/A",  // TODO (woodser): no timelocked tx in xmr, so part of popup message is n/a
                        -1);
                break;
        }

        acceptMediationResultPopup = new Popup().width(900)
                .headLine(headLine)
                .instruction(message)
                .actionButtonText(actionButtonText)
                .onAction(() -> {
                    model.dataModel.mediationManager.onAcceptMediationResult(trade,
                            () -> {
                                log.info("onAcceptMediationResult completed");
                                acceptMediationResultPopup = null;
                            },
                            errorMessage -> {
                                UserThread.execute(() -> {
                                    new Popup().error(errorMessage).show();
                                    if (acceptMediationResultPopup != null) {
                                        acceptMediationResultPopup.hide();
                                        acceptMediationResultPopup = null;
                                    }
                                });
                            });
                })
                .secondaryActionButtonText(Res.get("portfolio.pending.mediationResult.popup.openArbitration"))
                .onSecondaryAction(() -> {
                    model.dataModel.mediationManager.rejectMediationResult(trade);
                    model.dataModel.onOpenDispute();
                    acceptMediationResultPopup = null;
                })
                .onClose(() -> {
                    acceptMediationResultPopup = null;
                });

        if (hasSelfAccepted()) {
            acceptMediationResultPopup.disableActionButton();
        }

        acceptMediationResultPopup.show();
    }

    protected String getCurrencyName(Trade trade) {
        return CurrencyUtil.getNameByCode(getCurrencyCode(trade));
    }

    protected String getCurrencyCode(Trade trade) {
        return checkNotNull(trade.getOffer()).getCounterCurrencyCode();
    }

    protected boolean isXmrTrade() {
        return getCurrencyCode(trade).equals("XMR");
    }

    private void updateTradePeriodState(Trade.TradePeriodState tradePeriodState) {
        if (!trade.getDisputeState().isOpen()) {
            switch (tradePeriodState) {
                case FIRST_HALF:
                    // just for dev testing. not possible to go back in time ;-)
                    if (tradeStepInfo.getState() == TradeStepInfo.State.WARN_PERIOD_OVER) {
                        tradeStepInfo.setState(TradeStepInfo.State.WARN_HALF_PERIOD);
                    } else if (tradeStepInfo.getState() == TradeStepInfo.State.WARN_HALF_PERIOD) {
                        tradeStepInfo.setState(TradeStepInfo.State.SHOW_GET_HELP_BUTTON);
                        tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
                    }
                    break;
                case SECOND_HALF:
                    if (!trade.isPaymentReceived()) {
                        if (tradeStepInfo != null) {
                            tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getFirstHalfOverWarnText);
                            tradeStepInfo.setState(TradeStepInfo.State.WARN_HALF_PERIOD);
                        }
                    } else {
                        tradeStepInfo.setState(TradeStepInfo.State.SHOW_GET_HELP_BUTTON);
                    }
                    break;
                case TRADE_PERIOD_OVER:
                    if (tradeStepInfo != null) {
                        tradeStepInfo.setFirstHalfOverWarnTextSupplier(this::getPeriodOverWarnText);
                        tradeStepInfo.setState(TradeStepInfo.State.WARN_PERIOD_OVER);
                    }
                    break;
            }
        }
    }

//    private void checkIfLockTimeIsOver() {
//        if (trade.getDisputeState() == Trade.DisputeState.MEDIATION_CLOSED) {
//            Transaction delayedPayoutTx = trade.getDelayedPayoutTx();
//            if (delayedPayoutTx != null) {
//                long lockTime = delayedPayoutTx.getLockTime();
//                int bestChainHeight = model.dataModel.btcWalletService.getBestChainHeight();
//                long remaining = lockTime - bestChainHeight;
//                if (remaining <= 0) {
//                    openMediationResultPopup(Res.get("portfolio.pending.mediationResult.popup.headline", trade.getShortId()));
//                }
//            }
//        }
//    }

    protected void checkForUnconfirmedTimeout() {
        if (trade.isDepositsConfirmed()) return;
        long unconfirmedHours = Duration.between(trade.getDate().toInstant(), Instant.now()).toHours();
        if (unconfirmedHours >= 3 && !trade.hasFailed()) {
            String key = "tradeUnconfirmedTooLong_" + trade.getShortId();
            if (DontShowAgainLookup.showAgain(key)) {
                new Popup().warning(Res.get("portfolio.pending.unconfirmedTooLong", trade.getShortId(), unconfirmedHours))
                        .dontShowAgainId(key)
                        .closeButtonText(Res.get("shared.ok"))
                        .show();
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // TradeDurationLimitInfo
    ///////////////////////////////////////////////////////////////////////////////////////////

    private GridPane createInfoPopover() {
        GridPane infoGridPane = new GridPane();
        int rowIndex = 0;
        infoGridPane.setHgap(5);
        infoGridPane.setVgap(10);
        infoGridPane.setPadding(new Insets(10, 10, 10, 10));
        Label label = addMultilineLabel(infoGridPane, rowIndex++, Res.get("portfolio.pending.tradePeriodInfo"));
        label.setMaxWidth(450);

        HBox warningBox = new HBox();
        warningBox.setMinHeight(30);
        warningBox.setPadding(new Insets(5));
        warningBox.getStyleClass().add("warning-box");
        GridPane.setRowIndex(warningBox, rowIndex);
        GridPane.setColumnSpan(warningBox, 2);

        Label warningIcon = new Label();
        AwesomeDude.setIcon(warningIcon, AwesomeIcon.WARNING_SIGN);
        warningIcon.getStyleClass().add("warning");

        Label warning = new Label(Res.get("portfolio.pending.tradePeriodWarning"));
        warning.setWrapText(true);
        warning.setMaxWidth(410);

        warningBox.getChildren().addAll(warningIcon, warning);
        infoGridPane.getChildren().add(warningBox);

        return infoGridPane;
    }

    public void setChatCallback(TradeSubView.ChatCallback chatCallback) {
        this.chatCallback = chatCallback;
    }
}
