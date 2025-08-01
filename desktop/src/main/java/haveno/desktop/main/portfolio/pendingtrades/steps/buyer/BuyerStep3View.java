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

package haveno.desktop.main.portfolio.pendingtrades.steps.buyer;

import de.jensd.fx.fontawesome.AwesomeIcon;
import haveno.core.locale.Res;
import haveno.core.network.MessageState;
import haveno.desktop.components.TextFieldWithIcon;
import haveno.desktop.main.portfolio.pendingtrades.PendingTradesViewModel;
import haveno.desktop.main.portfolio.pendingtrades.steps.TradeStepView;
import haveno.desktop.util.Layout;
import javafx.beans.value.ChangeListener;
import javafx.scene.control.Label;
import javafx.scene.layout.GridPane;

import static haveno.desktop.util.FormBuilder.addMultilineLabel;
import static haveno.desktop.util.FormBuilder.addTitledGroupBg;
import static haveno.desktop.util.FormBuilder.addTopLabelTextFieldWithIcon;

public class BuyerStep3View extends TradeStepView {
    private final ChangeListener<MessageState> messageStateChangeListener;
    private TextFieldWithIcon textFieldWithIcon;


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Constructor, Initialisation
    ///////////////////////////////////////////////////////////////////////////////////////////

    public BuyerStep3View(PendingTradesViewModel model) {
        super(model);

        messageStateChangeListener = (observable, oldValue, newValue) -> {
            updateMessageStateInfo();
        };
    }

    @Override
    public void activate() {
        super.activate();

        model.getPaymentSentMessageStateProperty().addListener(messageStateChangeListener);

        updateMessageStateInfo();
    }

    public void deactivate() {
        super.deactivate();

        model.getPaymentSentMessageStateProperty().removeListener(messageStateChangeListener);
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Info
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected void addInfoBlock() {
        addTitledGroupBg(gridPane, ++gridRow, 2, getInfoBlockTitle(), Layout.GROUP_DISTANCE);
        infoLabel = addMultilineLabel(gridPane, gridRow, "", Layout.FIRST_ROW_AND_GROUP_DISTANCE);
        GridPane.setColumnSpan(infoLabel, 2);
        textFieldWithIcon = addTopLabelTextFieldWithIcon(gridPane, ++gridRow,
                Res.get("portfolio.pending.step3_buyer.wait.msgStateInfo.label"), 0).second;
    }

    @Override
    protected String getInfoBlockTitle() {
        return Res.get("portfolio.pending.step3_buyer.wait.headline");
    }

    @Override
    protected String getInfoText() {
        return Res.get("portfolio.pending.step3_buyer.wait.info", getCurrencyCode(trade));
    }

    private void updateMessageStateInfo() {
        MessageState messageState = model.getPaymentSentMessageStateProperty().get();
        textFieldWithIcon.setText(Res.get("message.state." + messageState.name()));
        Label iconLabel = textFieldWithIcon.getIconLabel();
        switch (messageState) {
            case UNDEFINED:
                textFieldWithIcon.setIcon(AwesomeIcon.QUESTION);
                iconLabel.getStyleClass().add("trade-msg-state-undefined");
                break;
            case SENT:
                textFieldWithIcon.setIcon(AwesomeIcon.ARROW_RIGHT);
                iconLabel.getStyleClass().add("trade-msg-state-sent");
                break;
            case ARRIVED:
                textFieldWithIcon.setIcon(AwesomeIcon.OK);
                iconLabel.getStyleClass().add("trade-msg-state-arrived");
                break;
            case STORED_IN_MAILBOX:
                textFieldWithIcon.setIcon(AwesomeIcon.ENVELOPE_ALT);
                iconLabel.getStyleClass().add("trade-msg-state-stored");
                break;
            case ACKNOWLEDGED:
                textFieldWithIcon.setIcon(AwesomeIcon.OK_SIGN);
                iconLabel.getStyleClass().add("trade-msg-state-stored");
                break;
            case FAILED:
            case NACKED:
                textFieldWithIcon.setIcon(AwesomeIcon.EXCLAMATION_SIGN);
                iconLabel.getStyleClass().add("trade-msg-state-acknowledged");
                break;
        }
    }


    ///////////////////////////////////////////////////////////////////////////////////////////
    // Warning
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected String getFirstHalfOverWarnText() {
        String substitute = model.isBlockChainMethod() ?
                Res.get("portfolio.pending.step3_buyer.warn.part1a", getCurrencyCode(trade)) :
                Res.get("portfolio.pending.step3_buyer.warn.part1b");
        return Res.get("portfolio.pending.step3_buyer.warn.part2", substitute);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////
    // Dispute
    ///////////////////////////////////////////////////////////////////////////////////////////

    @Override
    protected String getPeriodOverWarnText() {
        return Res.get("portfolio.pending.step3_buyer.openForDispute");
    }

    @Override
    protected void applyOnDisputeOpened() {
    }
}


