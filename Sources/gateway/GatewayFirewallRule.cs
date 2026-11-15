using System;

internal static class GatewayFirewallRule {
    const string Ipv6Range="::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff";
    static bool SingleAddress(string actual,string wanted){
        return actual==wanted || actual==wanted+"/32" || actual==wanted+"/255.255.255.255";
    }
    static bool SingleInterface(object value,string name){
        var interfaces=value as Array;
        return interfaces!=null && interfaces.Rank==1 && interfaces.Length==1
            && String.Equals(interfaces.GetValue(interfaces.GetLowerBound(0)) as string,name,StringComparison.OrdinalIgnoreCase);
    }
    // Read back only properties managed by this service. Some port properties are
    // invalid until Protocol has been set to TCP on a newly created rule.
    internal static int Reconcile(dynamic rule,bool initialize,bool tun,string address,string adapter,Action writing){
        int changes=0;
        int protocol=tun?6:256;
        if(initialize||(int)rule.Protocol!=protocol){writing();rule.Protocol=protocol;changes++;}
        if(tun){
            if(initialize||(string)rule.LocalPorts!="34010"){writing();rule.LocalPorts="34010";changes++;}
            if(initialize||!SingleAddress((string)rule.LocalAddresses,address)){writing();rule.LocalAddresses=address;changes++;}
            if(initialize||!SingleInterface((object)rule.Interfaces,adapter)){writing();rule.Interfaces=new object[]{adapter};changes++;}
        }else if(initialize||!String.Equals((string)rule.RemoteAddresses,Ipv6Range,StringComparison.OrdinalIgnoreCase)){
            writing();rule.RemoteAddresses=Ipv6Range;changes++;
        }
        int direction=tun?1:2,action=tun?1:0;
        if(initialize||(int)rule.Direction!=direction){writing();rule.Direction=direction;changes++;}
        if(initialize||(int)rule.Action!=action){writing();rule.Action=action;changes++;}
        if(initialize||(int)rule.Profiles!=7){writing();rule.Profiles=7;changes++;}
        if(initialize||!(bool)rule.Enabled){writing();rule.Enabled=true;changes++;}
        return changes;
    }
}
