using System;
using System.IO;
using AdvancedAINetwork.Gateway;

public static class DnsTests {
    static void Require(bool condition) { if (!condition) throw new Exception("DNS parser assertion failed."); }
    static void Rejected(byte[] query, byte[] response) {
        bool rejected = false; int ttl;
        try { GatewayDns.Parse(query, response, out ttl); } catch (IOException) { rejected = true; }
        Require(rejected);
    }
    public static int Main() {
        byte[] query = GatewayDns.Query("example.com");
        byte[] response = new byte[query.Length + 16];
        Array.Copy(query, response, query.Length); response[2] = 0x81; response[3] = 0x80; response[7] = 1;
        byte[] record = { 0xc0,12,0,1,0,1,0,0,0,60,0,4,203,0,113,7 };
        Array.Copy(record, 0, response, query.Length, record.Length);
        int ttl; Require(GatewayDns.Parse(query, response, out ttl).ToString() == "203.0.113.7" && ttl == 60);
        var wrongId = (byte[])response.Clone(); wrongId[0] ^= 1; Rejected(query, wrongId);
        var wrongQuestion = (byte[])response.Clone(); wrongQuestion[13] ^= 1; Rejected(query, wrongQuestion);
        for (int length = 0; length < response.Length; length++) {
            var shortResponse = new byte[length]; Array.Copy(response, shortResponse, length); Rejected(query, shortResponse);
        }
        var pointer = (byte[])response.Clone(); pointer[query.Length] = 0x80; Rejected(query, pointer);
        var noAnswer = (byte[])response.Clone(); noAnswer[7] = 0; Rejected(query, noAnswer);
        var wrongOpcode = (byte[])response.Clone(); wrongOpcode[2] |= 8; Rejected(query, wrongOpcode);
        Console.WriteLine("PASS valid A response, identity/question validation, every truncation, malformed name, missing answer, and wrong opcode");
        return 0;
    }
}
