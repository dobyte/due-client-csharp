namespace Due;

using System;
using System.Timers;
using Due.Network;
using Due.Security;

// 连接处理器
public delegate void ConnectHandler(Client client);

// 断开连接处理器
public delegate void DisconnectHandler(Client client);

// 消息接收处理器
public delegate void ReceiveHandler(Client client, Message message);

// 心跳消息处理器
public delegate void HeartbeatHandler(Client client, Int64? millisecond);

public class Client
{
    // 默认心跳间隔
    const int DEFAULT_HEARTBEAT_INTERVAL = 10 * 1000;
    // 拨号地址
    private string? Addr { get; set; }
    // 网络层
    private INetwork Network { get; set; }
    // 打包器
    private Packer Packer { get; set; }
    // 定时器
    private Timer? Timer;
    // 心跳包
    private byte[]? HeartbeatBuffer;
    // 会话安全配置；为 null 时不启用会话安全
    private readonly SecurityOptions? securityOptions;
    // 握手状态
    private HandshakeClient? handshake;
    // 会话密钥
    private volatile Session? session;
    // 握手超时定时器
    private System.Threading.Timer? handshakeTimer;
    // 连接处理器
    private ConnectHandler? ConnectHandler;
    // 断开连接处理器
    private DisconnectHandler? DisconnectHandler;
    // 消息接收处理器
    private ReceiveHandler? ReceiveHandler;
    // 心跳消息处理器
    private HeartbeatHandler? HeartbeatHandler;

    public Client() : this(new Packer())
    {
    }

    public Client(string addr) : this(addr, new Packer())
    {
    }

    public Client(Packer packer) : this(new Tcp(packer), packer, DEFAULT_HEARTBEAT_INTERVAL)
    {
    }

    public Client(string addr, Packer packer) : this(addr, new Tcp(packer), packer, DEFAULT_HEARTBEAT_INTERVAL)
    {
    }

    public Client(string addr, int heartbeatInterval) : this(addr, new Tcp(new Packer()), new Packer(), heartbeatInterval)
    {
    }

    public Client(string addr, Packer packer, int heartbeatInterval) : this(addr, new Tcp(packer), packer, heartbeatInterval)
    {
    }

    public Client(string addr, Packer packer, SecurityOptions securityOptions) : this(addr, new Tcp(packer), packer, securityOptions, DEFAULT_HEARTBEAT_INTERVAL)
    {
    }

    public Client(INetwork network, Packer packer) : this(network, packer, DEFAULT_HEARTBEAT_INTERVAL)
    {
    }

    public Client(INetwork network, Packer packer, int heartbeatInterval) : this(network, packer, null, heartbeatInterval)
    {
    }

    public Client(INetwork network, Packer packer, SecurityOptions securityOptions) : this(network, packer, securityOptions, DEFAULT_HEARTBEAT_INTERVAL)
    {
    }

    public Client(INetwork network, Packer packer, SecurityOptions? securityOptions, int heartbeatInterval) : this(null, network, packer, securityOptions, heartbeatInterval)
    {
    }

    public Client(string addr, INetwork network, Packer packer, int heartbeatInterval) : this(addr, network, packer, null, heartbeatInterval)
    {
    }

    public Client(string? addr, INetwork network, Packer packer, SecurityOptions? securityOptions, int heartbeatInterval)
    {
        if (securityOptions != null && securityOptions.Verifier == null)
        {
            throw new ArgumentException("The verifier of the security options must not be null", nameof(securityOptions));
        }

        this.Addr = addr;
        this.Network = network;
        this.Packer = packer;
        this.securityOptions = securityOptions;

        if (heartbeatInterval > 0)
        {
            this.Timer = new Timer(heartbeatInterval);
            this.Timer.Elapsed += OnTimedEvent;
            this.HeartbeatBuffer = this.Packer.PackHeartbeat();
        }
        else
        {
            this.Timer = null;
        }

        this.BindNetworkEvents();
    }

    // 绑定网络层事件
    private void BindNetworkEvents()
    {
        this.Network.OnConnected = () =>
        {
            this.ResetSecurityState();

            if (this.securityOptions != null)
            {
                this.StartHandshake();
            }
            else
            {
                this.OnEstablished();
            }
        };

        this.Network.OnDisconnected = () =>
        {
            this.Timer?.Stop();

            this.StopHandshakeTimer();

            this.ResetSecurityState();

            if (this.DisconnectHandler != null)
            {
                this.DisconnectHandler(this);
            }
        };

        this.Network.OnPacket = (byte[] buff) =>
        {
            try
            {
                Frame frame = this.Packer.UnpackFrame(buff);

                if (frame.IsHeartbeat)
                {
                    if (this.HeartbeatHandler != null)
                    {
                        this.HeartbeatHandler(this, frame.Millisecond);
                    }
                }
                else if (frame.IsHandshake)
                {
                    this.HandleHandshake(frame.Payload!);
                }
                else
                {
                    byte[] payload = frame.Payload!;

                    if (this.securityOptions != null)
                    {
                        Session? current = this.session;

                        if (current == null)
                        {
                            Console.WriteLine("The security session is not established");
                            return;
                        }

                        try
                        {
                            payload = current.OpenMessage(payload, Direction.ServerToClient, frame.Route, frame.Seq);
                        }
                        catch (Exception e)
                        {
                            // 认证失败或重放：连接已不可信，直接断开
                            Console.WriteLine(e);
                            this.Network.Disconnect();
                            return;
                        }
                    }

                    if (this.ReceiveHandler != null)
                    {
                        this.ReceiveHandler(this, new Message(frame.Seq, frame.Route, this.Packer.Decode(payload)));
                    }
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        };
    }

    // 连接就绪：启动心跳并触发连接回调；安全模式下在握手完成后调用
    private void OnEstablished()
    {
        this.Heartbeat();
        this.Timer?.Start();

        if (this.ConnectHandler != null)
        {
            this.ConnectHandler(this);
        }
    }

    // 发起会话安全握手
    private void StartHandshake()
    {
        try
        {
            SecurityOptions options = this.securityOptions!;

            this.handshake = new HandshakeClient(options.Verifier!, options.Suites);

            byte[] hello = this.handshake.Hello();

            this.StartHandshakeTimer();

            if (!this.Network.Send(this.Packer.PackHandshake(hello)))
            {
                throw new Exception("Send client hello failed");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            this.Network.Disconnect();
        }
    }

    // 处理服务端握手帧
    private void HandleHandshake(byte[] payload)
    {
        HandshakeClient? current = this.handshake;

        if (current == null)
        {
            Console.WriteLine("Unexpected handshake frame");
            return;
        }

        try
        {
            Session established = current.Handle(payload, out byte[] finished);

            // 先发布会话，再回发 Finished：服务端确认后可能立即下发加密消息
            this.session = established;

            this.handshake = null;
            this.StopHandshakeTimer();

            if (!this.Network.Send(this.Packer.PackHandshake(finished)))
            {
                throw new Exception("Send finished frame failed");
            }

            this.OnEstablished();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
            this.Network.Disconnect();
        }
    }

    // 启动握手超时定时器
    private void StartHandshakeTimer()
    {
        int timeout = this.securityOptions!.HandshakeTimeout;

        if (timeout <= 0)
        {
            return;
        }

        this.StopHandshakeTimer();
        this.handshakeTimer = new System.Threading.Timer(this.HandleHandshakeTimeout, null, timeout, System.Threading.Timeout.Infinite);
    }

    // 停止握手超时定时器
    private void StopHandshakeTimer()
    {
        System.Threading.Timer? timer = this.handshakeTimer;

        if (timer == null)
        {
            return;
        }

        this.handshakeTimer = null;
        timer.Dispose();
    }

    // 握手超时：断开连接
    private void HandleHandshakeTimeout(object? state)
    {
        if (this.session != null)
        {
            return;
        }

        Console.WriteLine("The security handshake timed out");
        this.Network.Disconnect();
    }

    // 清理握手状态与会话密钥
    private void ResetSecurityState()
    {
        this.handshake = null;

        Session? current = this.session;
        this.session = null;
        current?.Dispose();
    }

    // 设置连接处理器
    public void OnConnect(ConnectHandler handler)
    {
        this.ConnectHandler = handler;
    }

    // 设置断开连接处理器
    public void OnDisconnect(DisconnectHandler handler)
    {
        this.DisconnectHandler = handler;
    }

    // 消息接收处理器
    public void OnReceive(ReceiveHandler handler)
    {
        this.ReceiveHandler = handler;
    }

    // 心跳消息处理器
    public void OnHeartbeat(HeartbeatHandler handler)
    {
        this.HeartbeatHandler = handler;
    }

    // 定时器
    private void OnTimedEvent(object? source, ElapsedEventArgs e)
    {
        this.Heartbeat();
    }

    // 连接服务器
    public bool Connect()
    {
        if (this.Addr == null)
        {
            return false;
        }

        return this.Connect(this.Addr);
    }

    // 连接服务器
    public bool Connect(string addr)
    {
        return this.Network.Connect(addr);
    }

    // 发送数据
    public bool Send(Int32 route, Int32? seq, byte[]? data)
    {
        try
        {
            if (this.securityOptions != null)
            {
                Session? current = this.session;

                if (current == null)
                {
                    Console.WriteLine("The security session is not established");
                    return false;
                }

                data = current.SealMessage(data, Direction.ClientToServer, route, seq ?? 0);
            }

            byte[] buffer = this.Packer.PackMessage(route, seq, data);
            return this.Network.Send(buffer);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }

        return false;
    }

    // 发送数据
    public bool Send(Int32 route, Int32? seq, object? data)
    {
        try
        {
            if (this.securityOptions != null)
            {
                Session? current = this.session;

                if (current == null)
                {
                    Console.WriteLine("The security session is not established");
                    return false;
                }

                byte[]? payload = this.Packer.Encode(data);
                payload = current.SealMessage(payload, Direction.ClientToServer, route, seq ?? 0);

                return this.Network.Send(this.Packer.PackMessage(route, seq, payload));
            }

            byte[] buffer = this.Packer.PackMessage(route, seq, data);
            return this.Network.Send(buffer);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }

        return false;
    }

    // 检测客户端是否已连接
    public bool IsConnected()
    {
        return this.Network.IsConnected();
    }

    // 断开连接
    public void Disconnect()
    {
        this.StopHandshakeTimer();
        this.ResetSecurityState();

        this.Network.Disconnect();
    }

    // 发送心跳包
    private void Heartbeat()
    {
        if (this.HeartbeatBuffer != null)
        {
            this.Network.Send(this.HeartbeatBuffer);
        }
    }
}
