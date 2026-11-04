using System;
using System.Runtime.InteropServices;
public static class NativeBridge {
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate int OwnerSelector(uint pid);
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)] public delegate void LogCallback(IntPtr text);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="AdvancedAINetwork_SetRelayEndpoint")] public static extern bool SetRelayEndpoint(uint address,uint index);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="AdvancedAINetwork_SetOwnerSelector")] public static extern bool SetOwnerSelector(OwnerSelector callback,uint proxy,ushort front);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="ProxyBridge_AddProxyConfig")] public static extern uint AddProxy(int type,string host,ushort port,string user,string password,bool domain);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="ProxyBridge_SetLogCallback")] public static extern void SetLogCallback(LogCallback callback);
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="ProxyBridge_Start")] public static extern bool Start();
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="ProxyBridge_Stop")] public static extern bool Stop();
    [DllImport("ProxyBridgeCore.dll",CallingConvention=CallingConvention.Cdecl,EntryPoint="AdvancedAINetwork_EngineAlive")] public static extern bool Alive();
}
