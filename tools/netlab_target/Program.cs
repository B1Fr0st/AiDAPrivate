using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

Console.WriteLine("NetLabTarget starting...");
Console.WriteLine($"PID: {Environment.ProcessId}");
Console.WriteLine("Press Ctrl+C to stop. Generating TCP/UDP/HTTP/HTTPS/DNS traffic...");

var tcpServerTask = RunTcpEchoServerAsync(7777, cts.Token);
var udpServerTask = RunUdpSinkAsync(9001, cts.Token);
var trafficTask = RunTrafficLoopAsync(cts.Token);

await Task.WhenAll(tcpServerTask, udpServerTask, trafficTask);

static async Task RunTcpEchoServerAsync(int port, CancellationToken token)
{
    var listener = new TcpListener(IPAddress.Loopback, port);
    listener.Start();
    Console.WriteLine($"TCP echo server listening on 127.0.0.1:{port}");

    try
    {
        while (!token.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(token);
            _ = Task.Run(() => HandleTcpClientAsync(client, token), token);
        }
    }
    catch (OperationCanceledException)
    {
    }
    finally
    {
        listener.Stop();
    }
}

static async Task HandleTcpClientAsync(TcpClient client, CancellationToken token)
{
    using (client)
    {
        using var stream = client.GetStream();
        var buf = new byte[4096];

        try
        {
            while (!token.IsCancellationRequested)
            {
                var read = await stream.ReadAsync(buf.AsMemory(0, buf.Length), token);
                if (read <= 0)
                {
                    break;
                }

                // Echo back the data unchanged.
                await stream.WriteAsync(buf.AsMemory(0, read), token);
            }
        }
        catch
        {
        }
    }
}

static async Task RunUdpSinkAsync(int port, CancellationToken token)
{
    using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
    Console.WriteLine($"UDP sink listening on 127.0.0.1:{port}");

    try
    {
        while (!token.IsCancellationRequested)
        {
            _ = await udp.ReceiveAsync(token);
        }
    }
    catch (OperationCanceledException)
    {
    }
}

static async Task RunTrafficLoopAsync(CancellationToken token)
{
    using var http = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(10)
    };

    var cycle = 0;

    while (!token.IsCancellationRequested)
    {
        cycle++;
        Console.WriteLine($"[Cycle {cycle}] generating traffic...");

        await DoDnsAsync();
        await DoHttpAsync(http);
        await DoHttpsAsync(http);
        await DoLocalTcpAsync(token);
        await DoUdpAsync(token);

        await Task.Delay(TimeSpan.FromSeconds(3), token);
    }
}

static async Task DoDnsAsync()
{
    try
    {
        var hosts = new[] { "example.com", "microsoft.com", "localhost" };
        foreach (var h in hosts)
        {
            _ = await Dns.GetHostAddressesAsync(h);
        }
    }
    catch
    {
    }
}

static async Task DoHttpAsync(HttpClient http)
{
    try
    {
        using var resp = await http.GetAsync("http://example.com/");
        _ = await resp.Content.ReadAsStringAsync();
    }
    catch
    {
    }
}

static async Task DoHttpsAsync(HttpClient http)
{
    try
    {
        using var resp = await http.GetAsync("https://example.com/");
        _ = await resp.Content.ReadAsStringAsync();
    }
    catch
    {
    }
}

static async Task DoLocalTcpAsync(CancellationToken token)
{
    try
    {
        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, 7777, token);

        using var stream = client.GetStream();

        // Contains a deterministic test pattern for packet modification rules.
        var payload = Encoding.ASCII.GetBytes("MAGIC_PATTERN_DEADBEEF_TEST_PAYLOAD_1234567890");
        await stream.WriteAsync(payload.AsMemory(0, payload.Length), token);

        var recv = new byte[512];
        _ = await stream.ReadAsync(recv.AsMemory(0, recv.Length), token);

        // Keep one long-lived connection periodically to test kill_connection behavior.
        await Task.Delay(1500, token);
    }
    catch
    {
    }
}

static async Task DoUdpAsync(CancellationToken token)
{
    try
    {
        using var udp = new UdpClient();
        var data = Encoding.ASCII.GetBytes("UDP_TEST_PACKET_PAYLOAD_DEADBEEF");
        await udp.SendAsync(data, data.Length, "127.0.0.1", 9001);
    }
    catch
    {
    }
}
