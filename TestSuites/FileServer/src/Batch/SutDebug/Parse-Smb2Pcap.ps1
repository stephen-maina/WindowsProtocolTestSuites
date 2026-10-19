param([string]$Pcap, [string]$FromUtc, [string]$ToUtc, [int]$Port = 445)
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.IO;
public static class P {
  public static List<string> Run(string path, DateTime from, DateTime to, int port) {
    var o = new List<string>(); var b = File.ReadAllBytes(path); int i = 0; int tsres = 6;
    while (i + 12 <= b.Length) {
      uint t = BitConverter.ToUInt32(b, i), l = BitConverter.ToUInt32(b, i + 4); if (l < 12) break;
      if (t == 1) { int p = i + 8 + 8; while (p + 4 <= i + l - 4) { ushort c = BitConverter.ToUInt16(b, p), n = BitConverter.ToUInt16(b, p + 2); if (c == 9 && n >= 1) tsres = b[p + 4]; if (c == 0) break; p += 4 + ((n + 3) & ~3); } }
      if (t == 6) {
        ulong hi = BitConverter.ToUInt32(b, i + 12), lo = BitConverter.ToUInt32(b, i + 16); ulong ts = (hi << 32) | lo;
        double div = tsres == 9 ? 1e9 : (tsres == 6 ? 1e6 : 1e3); var dt = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(ts / div);
        int cap = (int)BitConverter.ToUInt32(b, i + 20), d = i + 28;
        if (dt >= from && dt <= to && cap > 54) {
          int et = (b[d + 12] << 8) | b[d + 13], ip = d + 14;
          if (et == 0x8100) { et = (b[d + 16] << 8) | b[d + 17]; ip = d + 18; }
          if (et == 0x0800 && b[ip + 9] == 6) {
            int ihl = (b[ip] & 15) * 4, tcp = ip + ihl, thl = (b[tcp + 12] >> 4) * 4, pl = tcp + thl;
            int sp = (b[tcp] << 8) | b[tcp + 1], dp = (b[tcp + 2] << 8) | b[tcp + 3]; int end = d + cap;
            if ((sp == port || dp == port) && pl + 8 < end) {
              string dir = dp == port ? "C->S" : "S->C"; int s = pl + 4;
              if (b[s] == 0xFE && b[s+1]=='S') {
                ushort cmd = BitConverter.ToUInt16(b, s + 12); uint st = BitConverter.ToUInt32(b, s + 8), fl = BitConverter.ToUInt32(b, s + 16);
                ulong mid = BitConverter.ToUInt64(b, s + 24); ulong sid = BitConverter.ToUInt64(b, s + 40);
                bool signed = (fl & 8) != 0; bool zero = true; for (int k = 0; k < 16; k++) if (b[s + 48 + k] != 0) zero = false;
                o.Add(dt.ToString("HH:mm:ss.ffffff") + " " + dir + " cmd=" + cmd + " status=0x" + st.ToString("X8") + " flags=0x" + fl.ToString("X") + (signed ? " SIGNED" : "") + (signed && zero ? "(zero-sig)" : "") + " msgid=" + mid + " sess=" + sid);
              } else if (b[s] == 0xFD && b[s+1]=='S') o.Add(dt.ToString("HH:mm:ss.ffffff") + " " + dir + " TRANSFORM(encrypted) len=" + (end - pl));
            }
          }
        }
      }
      i += (int)l;
    }
    return o;
  }
}
'@
$f = [DateTime]::Parse($FromUtc).ToUniversalTime(); $t = [DateTime]::Parse($ToUtc).ToUniversalTime()
[P]::Run($Pcap, $f, $t, $Port)
