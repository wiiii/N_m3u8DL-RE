using System.Security.Cryptography;

namespace N_m3u8DL_RE.Crypto;

/// <summary>
/// 优酷 copyrightDRM（AES_128_YK / DEYK）TS 分片就地解密。
/// 算法（2026-08-30 实证确定，对真实样本 seg_full.bin 3412952B 的
/// ffprobe 全解码零错误 + 366 帧 = 366 PES、ADTS 650 帧完整、PSI 5
/// 个包 0 改动）：
///   1. 跳过每个 188 字节 TS 包的 4 字节头与适配字段；
///   2. 跳过 9 字节 PES 头 + PES_header_data_length（仅当 PUSI=1 且载荷
///      以 00 00 01 起始时认定 PES）；
///   3. 把同一 PID 下、跨多个 TS 包、但属于同一 PES 的剩余载荷字节合并
///      （以 PUSI=1 划分 PES 边界）；
///   4. 对该 PES 载荷的前 floor(n/16)*16 字节做 AES-128-ECB 解密
///      （PaddingMode.None），尾部 n%16 字节保持原样；
///   5. 写回原 TS 包对应偏移。
/// 仅当 PUSI=1 且载荷以 00 00 01 起始时认定 PES；PSI（PAT/PMT/SDT）原
/// 样保留。N_m3u8DL-RE 上游 0.6.0 不含此方法。
/// </summary>
internal static class YkUtil
{
    private const int TsPacketSize = 188;
    private const int AesBlockSize = 16;

    public static byte[] DecryptYkTs(byte[] data, byte[] key)
    {
        if (data.Length == 0) return data;
        if (data.Length % TsPacketSize != 0)
            throw new InvalidDataException(
                $"Yk 分片大小不是 {TsPacketSize} 的整数倍: {data.Length}");
        if (key.Length != AesBlockSize)
            throw new InvalidDataException(
                $"YK 密钥必须是 {AesBlockSize} 字节，当前为 {key.Length} 字节");

        int packetCount = data.Length / TsPacketSize;
        var output = (byte[])data.Clone();

        // slots[i] = (payloadStart, payloadLen, isPesStart, pid)
        // payloadStart = -1 表示该包不参与（同步丢失/无载荷）
        var slots = new (int start, int len, bool isPes, int pid)[packetCount];
        for (int i = 0; i < packetCount; i++)
        {
            int baseOff = i * TsPacketSize;
            int start = -1, len = 0, pid = 0;
            bool isPes = false;

            if (data[baseOff] == 0x47)
            {
                pid = ((data[baseOff + 1] & 0x1f) << 8) | data[baseOff + 2];
                int pusi = (data[baseOff + 1] >> 6) & 0x1;
                int afc = (data[baseOff + 3] >> 4) & 0x3;
                int off = 4;
                if ((afc & 0x2) != 0) off += 1 + data[baseOff + 4];
                if (off <= TsPacketSize && (afc & 0x1) != 0)
                {
                    int payloadStart = off;
                    if (pusi == 1 && off + 9 <= TsPacketSize
                        && data[baseOff + off] == 0
                        && data[baseOff + off + 1] == 0
                        && data[baseOff + off + 2] == 1)
                    {
                        isPes = true;
                        payloadStart = off + 9 + data[baseOff + off + 8];
                    }
                    if (payloadStart <= TsPacketSize)
                    {
                        start = payloadStart;
                        len = TsPacketSize - payloadStart;
                    }
                }
            }
            slots[i] = (start, len, isPes, pid);
        }

        using var aes = Aes.Create();
        aes.KeySize = 128;
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        for (int i = 0; i < packetCount; i++)
        {
            if (!slots[i].isPes) continue;
            int pid = slots[i].pid;
            var grp = new List<int> { i };
            for (int k = i + 1; k < packetCount; k++)
            {
                if (slots[k].start < 0) continue;   // 跳过无载荷包（如 PCR-only）
                if (slots[k].pid != pid) break;      // 换 PID，结束
                if (slots[k].isPes) break;           // 下一个 PES 起始，结束
                grp.Add(k);
            }
            DecryptOnePes(data, output, slots, aes, grp);
        }
        return output;
    }

    private static void DecryptOnePes(
        byte[] data, byte[] output,
        (int start, int len, bool isPes, int pid)[] slots,
        Aes aes, List<int> grp)
    {
        int total = 0;
        foreach (int idx in grp) total += slots[idx].len;
        if (total == 0) return;

        var buf = new byte[total];
        int pos = 0;
        foreach (int idx in grp)
        {
            int s = slots[idx].start, l = slots[idx].len;
            Buffer.BlockCopy(data, idx * TsPacketSize + s, buf, pos, l);
            pos += l;
        }

        int full = total - total % AesBlockSize;
        var merged = new byte[total];
        if (full > 0)
        {
            using var dec = aes.CreateDecryptor();
            var decBytes = dec.TransformFinalBlock(buf, 0, full);
            Buffer.BlockCopy(decBytes, 0, merged, 0, full);
        }
        Buffer.BlockCopy(buf, full, merged, full, total - full);

        pos = 0;
        foreach (int idx in grp)
        {
            int s = slots[idx].start, l = slots[idx].len;
            Buffer.BlockCopy(merged, pos, output, idx * TsPacketSize + s, l);
            pos += l;
        }
    }
}
