using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using NetFrameworkComms.Common;

namespace NetFrameworkComms.Providers
{
    public class TlsConnection
    {
        public TcpClient Client;
        public SslStream Stream;
    }
    
    public class TlsTcpServer
    {
        private static X509Certificate _serverCertificate;
        private TcpListener _server;
        private readonly List<TlsConnection> _connections = new List<TlsConnection>();
        private bool _listening;
        private readonly Encoding _encoding = Encoding.GetEncoding(28591);
        private const int BufferSize = 4096;

        public int Port { get; set; }
        public string Name { get; set; }
        
        public event EventHandler<DataEventArgs> DataReceived;
        public event EventHandler<ListeningEventArgs> Listening;

        public TlsTcpServer()
        {
        }

        private X509Certificate GetServerCertificate()
        {
            if (Directory.Exists($"\\user\\certificates\\{Name}"))
            {
                if (File.Exists($"\\user\\certificates\\{Name}\\server.pfx"))
                {
                    return X509Certificate.CreateFromCertFile($"\\user\\certificates\\{Name}\\server.pfx");
                }
            }
            return null;
        }

        private async Task ListenAsync()
        {
            _server = new TcpListener(System.Net.IPAddress.Any, Port);
            _server.Start();

            _listening = true;
            Listening?.Invoke(this, new ListeningEventArgs(){ Listening = true });
            
            while (_listening)
            {
                try
                {
                    var client = await _server.AcceptTcpClientAsync();
                    _ = Task.Run(() => { ClientSession(client); });
                }
                catch (Exception e)
                {
                    //Todo Logging
                }
            }
            Listening?.Invoke(this, new ListeningEventArgs(){ Listening = false });
            _listening = false;
        }

        private void ClientSession(TcpClient client)
        {
            var clientIpEndpoint = client.Client.RemoteEndPoint as System.Net.IPEndPoint;
            var connection = new TlsConnection() { Client = client };
            _connections.Add(connection);
            try
            {
                using (var stream =  new SslStream(client.GetStream(), false))
                {
                    connection.Stream = stream;
                    stream.AuthenticateAsServer(_serverCertificate, false, SslProtocols.Tls12, false);
                    var data = new byte[BufferSize];
                    int i;

                    while ((i = stream.Read(data, 0, data.Length)) != 0)
                    {
                        if (i > 0)
                        {
                            DataReceived?.Invoke(this, new DataEventArgs() { Data = _encoding.GetString(data.Take(i).ToArray())});
                        }
                    }
                }

                if (client.Connected)
                {
                    client.Close();
                    client.Dispose();
                }

                _connections.Remove(connection);
            }
            catch (Exception e)
            {
                //Todo Logging
            }
        }

        private void SendMessage(SslStream stream, string msg)
        {
            var bytes = Encoding.ASCII.GetBytes(msg);
            stream.Write(bytes, 0, bytes.Length);
        }

        public void Send(string message)
        {
            foreach (var connection in _connections.ToArray())
            {
                if (connection.Client.Connected)
                {
                    SendMessage(connection.Stream, message);
                }
                else
                {
                    _connections.Remove(connection);
                    connection.Client.Close();
                    connection.Client.Dispose(); 
                }
            }
        }

        public void Connect()
        {
            if (_listening)
                return;
            _serverCertificate = GetServerCertificate();
            if (_serverCertificate == null)
            {
                //Todo Logging
                return;
            }
            _ = ListenAsync();
        }

        public void Disconnect()
        {
            foreach (var connection in _connections.ToArray())
            {
                connection.Client.Close();
                _connections.Remove(connection);
            }

            _server.Stop();
            _listening = false;
        }
    }
}