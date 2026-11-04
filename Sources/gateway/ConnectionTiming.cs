using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace AdvancedAINetwork.Gateway {
    // Optional, bounded diagnostics. The relay never waits for disk or the writer.
    internal sealed class ConnectionTimingLog : IDisposable {
        readonly string marker, output;
        readonly BlockingCollection<object> queue = new BlockingCollection<object>(1024);
        readonly JavaScriptSerializer json = new JavaScriptSerializer();
        readonly Timer timer;
        long expires, nextId;
        int flushing;
        volatile bool closed, full;
        const int Limit = 8 * 1024 * 1024;

        internal ConnectionTimingLog(string root) {
            marker = Path.Combine(root,"connection-timing.until");
            output = Path.Combine(root,"connection-timing.jsonl");
            timer = new Timer(_ => Flush(),null,0,1000);
        }
        internal bool Enabled { get { return !closed && !full && DateTime.UtcNow.Ticks < Interlocked.Read(ref expires); } }
        internal ConnectionTiming Begin(int listener, int peer) {
            if (!Enabled) return null;
            var trace = new ConnectionTiming(this,Interlocked.Increment(ref nextId));
            trace.Mark("accept",new { listener, peer_port=peer });
            return trace;
        }
        internal void Post(object row) { if (Enabled) queue.TryAdd(row); }
        void Flush() {
            if (Interlocked.Exchange(ref flushing,1)!=0) return;
            try {
                if (closed || full) return;
                DateTime end;
                string value = File.Exists(marker) ? File.ReadAllText(marker).Trim() : "";
                bool valid = DateTime.TryParseExact(value,"o",CultureInfo.InvariantCulture,DateTimeStyles.RoundtripKind,out end);
                Interlocked.Exchange(ref expires,valid ? end.ToUniversalTime().Ticks : 0);
                if (queue.Count == 0) return;
                using (var stream = new FileStream(output,FileMode.Append,FileAccess.Write,FileShare.ReadWrite)) {
                    object row;
                    for (int i=0; i<1024 && queue.TryTake(out row); i++) {
                        byte[] line=Encoding.UTF8.GetBytes(json.Serialize(row)+"\n");
                        if (stream.Position+line.Length>Limit) {full=true;return;}
                        stream.Write(line,0,line.Length);
                    }
                }
            // An optional diagnostic writer must not take down the service.
            } catch (Exception) {Interlocked.Exchange(ref expires,0);}
            finally {Interlocked.Exchange(ref flushing,0);}
        }
        public void Dispose() {closed=true;timer.Dispose();}
    }

    internal sealed class ConnectionTiming {
        readonly ConnectionTimingLog sink;
        readonly long id;
        readonly Stopwatch clock = Stopwatch.StartNew();
        readonly long[] bytes = new long[4], last = {-1,-1,-1,-1}, lastEvent = {-1,-1,-1,-1};
        static readonly string[] Names = {"client_read","upstream_write","upstream_read","client_write"};
        int failed;
        internal string Stage="client_greeting";
        internal ConnectionTiming(ConnectionTimingLog sink,long id) {this.sink=sink;this.id=id;}
        internal void Mark(string name,object detail=null) {
            sink.Post(new {utc=DateTime.UtcNow.ToString("o"),connection=id,ms=clock.ElapsedMilliseconds,kind=name,detail});
        }
        internal void Phase(string name) {Stage=name;Mark(name);}
        internal void Data(int direction,int count) {
            if (!sink.Enabled) return;
            long now=clock.ElapsedMilliseconds;
            long previous=Interlocked.Exchange(ref last[direction],now);
            long total=Interlocked.Add(ref bytes[direction],count);
            // Each slot is written by only one pump. Keep the last exact timestamps
            // even between samples, including on long-lived encrypted connections.
            if (previous>=0 && now-lastEvent[direction]<1000) return;
            lastEvent[direction]=now;
            Mark(Names[direction],new {total_bytes=total,gap_ms=previous<0?(long?)null:now-previous,
                last_upstream_write_ms=Interlocked.Read(ref last[1]),last_upstream_read_ms=Interlocked.Read(ref last[2])});
        }
        internal void Error(string where,Exception error) {
            if (Interlocked.Exchange(ref failed,1)!=0) return;
            var cause=error.GetBaseException();
            var socket=cause as SocketException;
            Mark("error",new {stage=where,type=cause.GetType().Name,socket_code=socket==null?(int?)null:socket.NativeErrorCode,
                last_upstream_write_ms=Interlocked.Read(ref last[1]),last_upstream_read_ms=Interlocked.Read(ref last[2])});
        }
        internal void End() {Mark("end",new {uploaded=Interlocked.Read(ref bytes[1]),downloaded=Interlocked.Read(ref bytes[3])});}
    }
}
