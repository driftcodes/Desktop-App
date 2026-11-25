#pragma once

#include <QThread>
#include <QElapsedTimer>
#include <QPointer>
#include <QTcpSocket>
#include <QTimer>

#include <atomic>

#include "engine/connectionmanager/connectors/iconnection.h"
#include "engine/connectionmanager/connectors/openvpn/openvpnsessionparams.h"
#include "engine/connectionmanager/connectors/openvpn/stunnelmanager.h"
#include "engine/connectionmanager/connectors/openvpn/wstunnelmanager.h"
#include "engine/customconfigs/ovpnroutingpolicy.h"
#include "engine/helper/helper.h"
#include "types/protocol.h"
#include "utils/boost_includes.h"

class OpenVPNConnection : public IConnection
{
    Q_OBJECT

public:
    explicit OpenVPNConnection(QObject *parent, Helper *helper, types::Protocol protocol, const OpenVpnSessionParams &sessionParams);
    ~OpenVPNConnection() override;

    void teardown() override;

    void startConnect() override;
    void startDisconnect() override;
    bool isDisconnected() const override;
    bool isAllowFirewallAfterConnectionRuntime() const override;

    void continueWithUserInput(const UserInputResponse &response) override;

protected:
    void prepareImpl() override;
    void run() override;

private slots:
    void onKillControllerTimer();
    void onWrapperStarted();

private:
#ifdef WINDSCRIBE_BUILD_TESTS
    friend class TestOpenVPNConnection;
#endif
    static constexpr int MAX_WAIT_OPENVPN_ON_START = 20000;
    static constexpr int MANAGEMENT_SOCKET_RETRY_DELAY_MS = 100;

    Helper *helper_;
    OpenVpnSessionParams sessionParams_;
    StunnelManager *stunnelManager_;
    WstunnelManager *wstunnelManager_;
    std::atomic<bool> bStopThread_;

    boost::asio::io_context io_context_;
    boost::asio::steady_timer connectRetryTimer_;
#ifdef Q_OS_WIN
    // Holds connected() back until the adapter address is Preferred; see NetworkUtils_win::kAddressPreferredMaxWaitMs.
    boost::asio::steady_timer adapterReadyTimer_;
    QElapsedTimer adapterReadyElapsed_;
#endif

    QString config_;
    QString username_;
    QString password_;
    QString privKeyPassword_;
    bool isCustomConfig_;
    QString connectErrorDetail_;
    // Set once startConnect() runs; teardown() must not issue the mac route delete for a connector
    // that never dialed (the helper would be hit with another session's ip).
    bool isDialed_ = false;

    enum CONNECTION_STATUS {STATUS_DISCONNECTED, STATUS_CONNECTING, STATUS_CONNECTED_TO_SOCKET, STATUS_CONNECTED};
    std::atomic<CONNECTION_STATUS> currentState_;

    void setCurrentState(CONNECTION_STATUS state);
    void setCurrentStateAndEmitDisconnected(CONNECTION_STATUS state);
    void setCurrentStateAndEmitError(CONNECTION_STATUS state, ConnectError err);
    CONNECTION_STATUS getCurrentState() const;
    bool runOpenVPN();
    ConnectError launchFailureError() const;

    // Whether this attempt is dialed through the user's HTTP/SOCKS proxy: OpenVPN TCP only, never for
    // the emergency session. Imported (custom) configs are included.
    bool isProxyForwarded() const;
    bool isLoopbackProxy() const;
    // Final prepare step: when the proxy will be used, confirm it accepts a TCP connection before
    // OpenVPN is launched, so an unavailable proxy is reported instead of hanging in reconnect.
    void finishPrepare();
    void onProxyProbeFinished(bool reachable, const QString &reason);

    static constexpr int kProxyProbeTimeoutMs = 3000;
    QPointer<QTcpSocket> proxyProbeSocket_;
    QTimer proxyProbeTimer_;
    // What the final config itself says about default-gateway redirection; combined with the server's
    // push to decide whether the tunnel carries all IPv4 traffic (automatic firewall).
    customconfigs::OvpnRoutingPolicy routingPolicy_;
    QString takeConnectErrorDetail() override;

#ifdef Q_OS_WIN
    using ManagementSocket = boost::asio::ip::tcp::socket;
#else
    using ManagementSocket = boost::asio::local::stream_protocol::socket;
#endif

    struct StateVariables
    {
        boost::scoped_ptr<ManagementSocket> socket;
        boost::scoped_ptr<boost::asio::streambuf> buffer;
        bool bTapErrorEmited;
        bool bWasStateNotification;
        bool bWasSecondAttemptToStartOpenVpn;
        bool bWasSocketConnected;

        bool isAcceptSigTermCommand_;
        bool bSigTermSent;
        bool bNeedSendSigTerm;

        bool bFirstCalcStat;
        quint64 prevBytesRcved;
        quint64 prevBytesXmited;

        unsigned int openVpnPort;
        unsigned long openVpnPid;

        QElapsedTimer elapsedTimer;

        StateVariables()
        {
            reset();
        }

        void reset()
        {
            socket.reset();
            buffer.reset();

            bSigTermSent = false;
            bTapErrorEmited = false;
            bWasStateNotification = false;
            bWasSecondAttemptToStartOpenVpn = false;
            bFirstCalcStat = true;
            prevBytesRcved = 0;
            prevBytesXmited = 0;
            openVpnPort = 0;
            openVpnPid = 0;
            bWasSocketConnected = false;
            bNeedSendSigTerm = false;
            isAcceptSigTermCommand_ = false;
        }
    };

    StateVariables stateVariables_;
    // Every option line the server pushed this session (connection thread only), and whether the
    // tunnel then carries all IPv4 traffic, published for the engine thread.
    QStringList pushedOptions_;
    std::atomic<bool> isFullIpv4Tunnel_{false};

    static constexpr int KILL_TIMEOUT = 10000;
    QTimer killControllerTimer_;

    AdapterGatewayInfo connectionAdapterInfo_;

    void funcRunOpenVPN();
#ifdef Q_OS_WIN
    void funcFailAdapterSetup();
    void funcFailDnsLeakFilter();
    void waitForAdapterReady(const boost::system::error_code &err);
#endif
    void asyncConnectToManagementSocket();
    void retryConnectToManagementSocket(const boost::system::error_code& err);
#ifdef Q_OS_WIN
    bool verifyOpenVpnPeer();
#endif
    void funcConnectToOpenVPN(const boost::system::error_code& err);
    void handleRead(const boost::system::error_code& err, size_t bytes_transferred);
    void funcDisconnect();

    void checkErrorAndContinue(boost::system::error_code &write_error, bool bWithAsyncReadCall);
    void emitAuthErrorAndSigTerm(boost::system::error_code &write_error);
    void continueWithUsernameAndPassword(const QString &username, const QString &password);
    void continueWithPassword(const QString &password);
    void continueWithPrivKeyPassword(const QString &password);
    void continueWithUsernameImpl();
    void continueWithPasswordImpl();
    void continueWithPrivKeyPasswordImpl();

    static QString sanitizeString(const QString &s);
    static QString redactManagementLine(const QString &line);

    bool parsePushReply(const QString &reply, AdapterGatewayInfo &outConnectionAdapterInfo, bool &outRedirectDefaultGateway);
    bool parseDeviceOpenedReply(const QString &reply, QString &outDeviceName);
    bool parseConnectedSuccessReply(const QString &reply, QString &outRemoteIp);
};
