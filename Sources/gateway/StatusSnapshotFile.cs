using System;
using System.IO;
using System.Threading;

// File.Replace may briefly deny an open on Windows, including opens that share DELETE.
// Read a new handle on each attempt. Never use a previous successful heartbeat.
internal static class StatusSnapshotFile {
    internal static T Read<T>(Func<T> read) {
        for(int attempt=0;;attempt++) {
            try { return read(); }
            catch(IOException e) { if(!Retryable(e,attempt))throw; }
            catch(UnauthorizedAccessException e) { if(!Retryable(e,attempt))throw; }
            Thread.Sleep(12 << attempt);
        }
    }
    static bool Retryable(Exception e,int attempt) {
        int error=e.HResult & 0xffff;
        return attempt<3 && (error==2 || error==5 || error==32 || error==33 || error==303);
    }
}
