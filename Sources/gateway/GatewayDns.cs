using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedAINetwork.Gateway {
    // Resolve over the same gateway, without consulting protected synthetic DNS
    // addresses or the machine's unrelated system proxy.
    public sealed class GatewayDns {
        readonly GatewayTransport transport;
        readonly GatewayTransport.Route route;
        readonly ConcurrentDictionary<string, Cache> cache = new ConcurrentDictionary<string, Cache>(StringComparer.OrdinalIgnoreCase);
        sealed class Cache { public IPAddress Address; public DateTime Until; }
        public GatewayDns(GatewayTransport transport, GatewayTransport.Route route=null) { this.transport = transport; this.route=route; }
        public IPAddress Resolve(string name) {
            IPAddress numeric;
            if (IPAddress.TryParse(name, out numeric)) {
                if (numeric.AddressFamily != AddressFamily.InterNetwork) throw new IOException("IPv6 is not enabled.");
                return numeric;
            }
            name = new IdnMapping().GetAscii(name.TrimEnd('.')).ToLowerInvariant();
            Cache hit;
            if (cache.TryGetValue(name, out hit) && hit.Until > DateTime.UtcNow) return hit.Address;
            byte[] query = Query(name);
            byte[] answer;
            using (var socket = transport.OpenUdp(IPAddress.Parse("1.1.1.1"), 53, route)) {
                socket.Client.Client.ReceiveTimeout = 2500;
                socket.Client.Send(query, query.Length);
                IPEndPoint peer = null;
                answer = socket.Client.Receive(ref peer);
            }
            if (answer.Length >= 4 && (answer[2] & 2) != 0) {
                using (var socket = transport.OpenTcp(IPAddress.Parse("1.1.1.1"), 53, route)) {
                    socket.Client.ReceiveTimeout = socket.Client.SendTimeout = 3000;
                    var stream = socket.Client.GetStream();
                    stream.WriteByte((byte)(query.Length >> 8)); stream.WriteByte((byte)query.Length);
                    stream.Write(query, 0, query.Length);
                    byte[] size = Read(stream, 2); answer = Read(stream, U16(size, 0));
                }
            }
            int ttl;
            IPAddress result = Parse(query, answer, out ttl);
            if (cache.Count < 4096) cache[name] = new Cache { Address = result, Until = DateTime.UtcNow.AddSeconds(Math.Min(ttl, 300)) };
            return result;
        }
        internal static byte[] Query(string name) {
            if (name.Length == 0 || name.Length > 253) throw new IOException("Invalid DNS name.");
            byte[] id = new byte[2]; using (var random = RandomNumberGenerator.Create()) random.GetBytes(id);
            var query = new List<byte> { id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
            foreach (string label in name.Split('.')) {
                if (label.Length == 0 || label.Length > 63) throw new IOException("Invalid DNS label.");
                foreach (char c in label) if (!(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_')) throw new IOException("Invalid DNS label.");
                query.Add((byte)label.Length); query.AddRange(Encoding.ASCII.GetBytes(label));
            }
            query.AddRange(new byte[] { 0, 0, 1, 0, 1 }); return query.ToArray();
        }
        static int U16(byte[] bytes, int offset) { if (offset + 2 > bytes.Length) throw new IOException("Truncated DNS response."); return bytes[offset] * 256 + bytes[offset + 1]; }
        static void SkipName(byte[] bytes, ref int offset) {
            for (int labels = 0; labels < 128; labels++) {
                if (offset >= bytes.Length) throw new IOException("Truncated DNS name.");
                int length = bytes[offset++];
                if (length == 0) return;
                if ((length & 192) == 192) { if (offset >= bytes.Length) throw new IOException("Truncated DNS pointer."); offset++; return; }
                if (length > 63 || offset + length > bytes.Length) throw new IOException("Invalid DNS label.");
                offset += length;
            }
            throw new IOException("Invalid DNS name.");
        }
        internal static IPAddress Parse(byte[] query, byte[] answer, out int ttl) {
            ttl = 0;
            if (answer.Length < 12 || answer[0] != query[0] || answer[1] != query[1] ||
                (answer[2] & 128) == 0 || (answer[2] & 120) != 0 || (answer[3] & 15) != 0 || U16(answer, 4) != 1)
                throw new IOException("DNS resolution did not return a valid response.");
            int offset = 12; SkipName(answer, ref offset);
            if (offset + 4 > answer.Length || U16(answer, offset) != 1 || U16(answer, offset + 2) != 1) throw new IOException("Unexpected DNS question.");
            // Match the uncompressed question emitted by the resolver.
            if (offset + 4 != query.Length) throw new IOException("DNS question mismatch.");
            for (int i = 12; i < query.Length; i++) if (answer[i] != query[i]) throw new IOException("DNS question mismatch.");
            offset += 4;
            int count = U16(answer, 6);
            for (int record = 0; record < count; record++) {
                SkipName(answer, ref offset);
                if (offset + 10 > answer.Length) throw new IOException("Truncated DNS record.");
                int type = U16(answer, offset), cls = U16(answer, offset + 2), length = U16(answer, offset + 8);
                uint lifetime = ((uint)answer[offset + 4] << 24) | ((uint)answer[offset + 5] << 16) | ((uint)answer[offset + 6] << 8) | answer[offset + 7];
                offset += 10;
                if (offset + length > answer.Length) throw new IOException("Truncated DNS data.");
                if (type == 1 && cls == 1 && length == 4) {
                    ttl = (int)Math.Min(lifetime, 300u);
                    return new IPAddress(new byte[] { answer[offset], answer[offset + 1], answer[offset + 2], answer[offset + 3] });
                }
                offset += length;
            }
            throw new IOException("DNS response has no IPv4 address.");
        }
        internal static byte[] Read(Stream stream, int count) {
            if (count < 1 || count > 65535) throw new IOException("Invalid response length.");
            var bytes = new byte[count];
            for (int position = 0; position < count;) { int read = stream.Read(bytes, position, count - position); if (read == 0) throw new EndOfStreamException(); position += read; }
            return bytes;
        }
    }
}
