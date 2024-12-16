using System;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using NetFrameworkComms.Common;
using Polly;

namespace NetFrameworkComms.Providers
{
    public class TlsTcpClient
    {
        private TcpClient _client;
        private SslStream _stream;
        private readonly object _lock = new object();
        private bool _isConnecting;
        private bool _disconnected;
        private bool _failure;
        private readonly Encoding _encoding = Encoding.GetEncoding(28591);
        private const int BufferSize = 4096;
        
        public int Port { get; set; }
        public string Host { get; set; }
        public event EventHandler<DataEventArgs> DataReceived;
        public event EventHandler<ConnectedEventArgs> Connected;

        public TlsTcpClient()
        {
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Ssl3 | SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
        }
        
        private async Task<bool> ConnectAsync()
        {
            lock (_lock)
            {
                if (_isConnecting || _client != null)
                {
                    return false;
                }
                _isConnecting = true;
            }

            _client = new TcpClient();
            _disconnected = false;
            await Policy.Handle<Exception>(e => !_disconnected)
                .WaitAndRetryForeverAsync(retryAttempt => (TimeSpan.FromSeconds(Math.Min(Math.Pow(2, retryAttempt), 60))), (exception, waitDuration) => {
                    if (!_failure)
                    {
                        //Todo Logging
                    }
                    _failure = true;
                })
                .ExecuteAndCaptureAsync(() => _client.ConnectAsync(Host, Port));
            if(!_disconnected)
            {
                _failure = false;
                _stream = new SslStream(_client.GetStream(), false, CertificateValidation);
                await _stream.AuthenticateAsClientAsync(Host);
                Connected?.Invoke(this, new ConnectedEventArgs { Connected = true });
                _ = Receive();
            }

            lock (_lock)
            {
                _isConnecting = false;
            }
            return !_failure;
        }
        
        private async Task Receive()
        {
            var data = new byte[BufferSize];
            try
            {
                int dataLength;
                while ((dataLength = await _stream.ReadAsync(data, 0, data.Length)) != 0 && !_disconnected)
                {
                    DataReceived?.Invoke(this,  new DataEventArgs(){ Data = _encoding.GetString(data.Take(dataLength).ToArray())});
                }
            }
            catch (Exception e)
            {
                //Todo Logging
            }
            Connected?.Invoke(this, new ConnectedEventArgs { Connected = false });
            _client?.Close();
            _client?.Dispose();
            _client = null;
            if (!_disconnected)
            {
                Thread.Sleep(500);
                _ = ConnectAsync();
            }	
        }
        
        private static bool CertificateValidation(Object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
            switch (sslPolicyErrors)
            {
                case SslPolicyErrors.None:
                case SslPolicyErrors.RemoteCertificateChainErrors:
                    return true;
                default:
                    return false;
            }
        }
        
        public void Disconnect()
        {
            _disconnected = true;
            _client?.Close();
            _client?.Dispose();
            _client = null;
        }
        
        public void Send(string data)
        {
            try
            {
                lock (_lock)
                {
                    if (_stream != null && _client != null)
                    {
                        var bytes = _encoding.GetBytes(data);
                        _stream.Write(bytes, 0, bytes.Length);
                    }
                }
            }
            catch (Exception e)
            {
                //Todo Logging
                Disconnect();
                _ = ConnectAsync();
            }
        }
    }
}