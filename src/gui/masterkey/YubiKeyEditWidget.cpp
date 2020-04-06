/*
 *  Copyright (C) 2018 KeePassXC Team <team@keepassxc.org>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "YubiKeyEditWidget.h"
#include "ui_YubiKeyEditWidget.h"

#include "config-keepassx.h"
#include "gui/MainWindow.h"
#include "gui/MessageBox.h"
#include "keys/CompositeKey.h"
#include "keys/YkChallengeResponseKey.h"

#include <QtConcurrent>

YubiKeyEditWidget::YubiKeyEditWidget(QWidget* parent)
    : KeyComponentWidget(parent)
    , m_compUi(new Ui::YubiKeyEditWidget())
{
    setComponentName(tr("YubiKey Challenge-Response"));
    setComponentDescription(
        tr("<p>If you own a <a href=\"https://www.yubico.com/\">YubiKey</a>, you can use it "
           "for additional security.</p><p>The YubiKey requires one of its slots to be programmed as "
           "<a href=\"https://www.yubico.com/products/services-software/personalization-tools/challenge-response/\">"
           "HMAC-SHA1 Challenge-Response</a>.</p>"));

    connect(YubiKey::instance(), SIGNAL(detectComplete(bool)), SLOT(hardwareKeyResponse(bool)), Qt::QueuedConnection);
}

YubiKeyEditWidget::~YubiKeyEditWidget()
{
}

bool YubiKeyEditWidget::addToCompositeKey(QSharedPointer<CompositeKey> key)
{
    QSharedPointer<YkChallengeResponseKey> keyPtr;
    if (!createCrKey(keyPtr, false)) {
        return false;
    }
    key->addChallengeResponseKey(keyPtr);

    return true;
}

bool YubiKeyEditWidget::validate(QString& errorMessage) const
{
    QSharedPointer<YkChallengeResponseKey> keyPtr;
    if (!createCrKey(keyPtr)) {
        errorMessage = tr("No YubiKey detected, please ensure it's plugged in.");
        return false;
    }

    return true;
}

QWidget* YubiKeyEditWidget::componentEditWidget()
{
    m_compEditWidget = new QWidget();
    m_compUi->setupUi(m_compEditWidget);

    QSizePolicy sp = m_compUi->yubikeyProgress->sizePolicy();
    sp.setRetainSizeWhenHidden(true);
    m_compUi->yubikeyProgress->setSizePolicy(sp);
    m_compUi->yubikeyProgress->setVisible(false);
    m_compUi->messageWidget->hide();

#ifdef WITH_XC_YUBIKEY
    connect(m_compUi->buttonRedetectYubikey, SIGNAL(clicked()), SLOT(pollYubikey()));
    connect(YubiKey::instance(), &YubiKey::userInteractionRequest, [this] {
        // Show the press notification if we are in an independent window (e.g., New DB Wizard)
        if (window() != getMainWindow()) {
            m_compUi->messageWidget->showMessage(tr("Please touch the button on your YubiKey!"),
                                                 MessageWidget::Information,
                                                 MessageWidget::DisableAutoHide);
        }
    });
    connect(YubiKey::instance(), &YubiKey::challengeCompleted, [this] { m_compUi->messageWidget->hide(); });

    pollYubikey();
#endif

    return m_compEditWidget;
}

void YubiKeyEditWidget::initComponentEditWidget(QWidget* widget)
{
    Q_UNUSED(widget);
    Q_ASSERT(m_compEditWidget);
    m_compUi->comboChallengeResponse->setFocus();
}

void YubiKeyEditWidget::pollYubikey()
{
#ifdef WITH_XC_YUBIKEY
    if (!m_compEditWidget) {
        return;
    }

    m_isDetected = false;
    m_compUi->comboChallengeResponse->clear();
    m_compUi->comboChallengeResponse->addItem(tr("Detecting Hardware Keys..."));
    m_compUi->buttonRedetectYubikey->setEnabled(false);
    m_compUi->comboChallengeResponse->setEnabled(false);
    m_compUi->yubikeyProgress->setVisible(true);

    YubiKey::instance()->findValidKeys();
#endif
}

void YubiKeyEditWidget::hardwareKeyResponse(bool found)
{
    if (!m_compEditWidget) {
        return;
    }

    m_compUi->comboChallengeResponse->clear();
    m_compUi->buttonRedetectYubikey->setEnabled(true);
    m_compUi->yubikeyProgress->setVisible(false);

    if (!found) {
        m_compUi->comboChallengeResponse->addItem(tr("No Hardware Keys Detected"));
        m_isDetected = false;
        return;
    }

    for (auto& slot : YubiKey::instance()->foundKeys()) {
        // add detected YubiKey to combo box and encode blocking mode in LSB, slot number in second LSB
        m_compUi->comboChallengeResponse->addItem(YubiKey::instance()->getDisplayName(slot),
                                                  QVariant::fromValue(slot));
    }

    m_isDetected = true;
    m_compUi->comboChallengeResponse->setEnabled(true);
}

bool YubiKeyEditWidget::createCrKey(QSharedPointer<YkChallengeResponseKey>& key, bool testChallenge) const
{
    Q_ASSERT(m_compEditWidget);
    if (!m_isDetected || !m_compEditWidget) {
        return false;
    }

    int selectionIndex = m_compUi->comboChallengeResponse->currentIndex();
    auto slot = m_compUi->comboChallengeResponse->itemData(selectionIndex).value<YubiKeySlot>();
    key.reset(new YkChallengeResponseKey(slot));
    if (testChallenge) {
        return key->challenge(QByteArray("0000"));
    }
    return true;
}
