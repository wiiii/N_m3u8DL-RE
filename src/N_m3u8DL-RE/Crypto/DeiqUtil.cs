using System.Security.Cryptography;

namespace N_m3u8DL_RE.Crypto;

/// <summary>
/// iQIYI DEIQ (DRM v3 / DCM) TS 分片解密工具。
/// 算法与 IQY-BAT 的 iqy_deiq.py（HmDX DeIQ 兼容）逐行对应，
/// 由下载器在下载完成后就地解密，无需外部 Python 依赖。
/// </summary>
internal static class DeiqUtil
{
    private const int TS_PACKET_SIZE = 188;
    // DCM 模式串 s1:9:10 的语义：每 10 个 16 字节块为一个循环，
    // 循环首块（index % CTR_CYCLE == 0）或最后一块走 AES-CTR（本实现用
    // AES-ECB(deiq_key, block_key[:12]+counter) 产生 keystream），其余块与自增计数器做 XOR。
    private const int CTR_CYCLE = 10;

    /// <summary>
    /// 解密一个 DEIQ TS 分片，返回普通 TS 字节。
    /// </summary>
    /// <param name="data">完整 TS 分片（多个 188 字节包）</param>
    /// <param name="deiqKey">16 字节 DEIQ 密钥（已由 --custom-hls-key 解码）</param>
    public static byte[] DecryptIqyTs(byte[] data, byte[] deiqKey)
    {
        if (data.Length % TS_PACKET_SIZE != 0)
            throw new InvalidDataException($"DEIQ 分片大小不是 {TS_PACKET_SIZE} 的整数倍: {data.Length}");

        // 每个 TS 分片内嵌 block_key：|v{32 hex}|
        byte[]? blockKey = FindBlockKey(data);
        if (blockKey == null)
            return data; // 无 block_key 标记，原样返回

        if (deiqKey.Length != 16)
            throw new InvalidDataException($"DEIQ 密钥长度必须是 16 字节，当前为 {deiqKey.Length} 字节");

        using var aes = Aes.Create();
        aes.KeySize = 128;
        aes.BlockSize = 128;
        aes.Key = deiqKey;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        var output = new MemoryStream(data.Length);
        var targetPids = new List<int>();
        var buffers = new Dictionary<int, PidBuffer>();

        void Flush(int pid)
        {
            if (!buffers.TryGetValue(pid, out var state) || state.Packets.Count == 0)
                return;
            byte[] decrypted = DecryptEs(state.Payload.ToArray(), blockKey, aes);
            int payloadOffset = 0;
            for (int i = 0; i < state.Packets.Count; i++)
            {
                byte[] packet = state.Packets[i];
                int offset = state.Offsets[i];
                int payloadSize = TS_PACKET_SIZE - offset;
                Buffer.BlockCopy(decrypted, payloadOffset, packet, offset, payloadSize);
                payloadOffset += payloadSize;
                output.Write(packet, 0, TS_PACKET_SIZE);
            }
            state.Packets.Clear();
            state.Offsets.Clear();
            state.Payload.SetLength(0);
        }

        for (int position = 0; position < data.Length; position += TS_PACKET_SIZE)
        {
            byte[] packet = new byte[TS_PACKET_SIZE];
            Buffer.BlockCopy(data, position, packet, 0, TS_PACKET_SIZE);
            if (packet[0] != 0x47)
                throw new InvalidDataException($"DEIQ 分片在偏移 {position} 处缺少 TS 同步字节");

            int pid = ((packet[1] & 0x1F) << 8) | packet[2];
            bool payloadUnitStart = (packet[1] & 0x40) != 0;

            if (payloadUnitStart && pid is >= 32 and <= 256 && !targetPids.Contains(pid) && targetPids.Count < 2)
            {
                targetPids.Add(pid);
                buffers[pid] = new PidBuffer();
            }

            if (!targetPids.Contains(pid))
            {
                output.Write(packet, 0, TS_PACKET_SIZE);
                continue;
            }

            int payloadStart = 4;
            if ((packet[3] & 0x20) != 0)
                payloadStart += 1 + packet[4];
            if (payloadStart > TS_PACKET_SIZE)
                throw new InvalidDataException($"DEIQ TS PID {pid} 的适配字段越界");

            byte[] payload = new byte[TS_PACKET_SIZE - payloadStart];
            Buffer.BlockCopy(packet, payloadStart, payload, 0, payload.Length);

            if (payloadUnitStart)
            {
                Flush(pid);
                if (payload.Length < 9)
                    throw new InvalidDataException($"DEIQ TS PID {pid} 的 PES 头不完整");
                int pesHeaderSize = 9 + payload[8];
                if (pesHeaderSize > payload.Length)
                    throw new InvalidDataException($"DEIQ TS PID {pid} 的 PES 头长度越界");
                payloadStart += pesHeaderSize;
                byte[] esPayload = new byte[payload.Length - pesHeaderSize];
                Buffer.BlockCopy(payload, pesHeaderSize, esPayload, 0, esPayload.Length);
                payload = esPayload;
            }

            PidBuffer state = buffers[pid];
            state.Packets.Add(packet);
            state.Offsets.Add(payloadStart);
            state.Payload.Write(payload, 0, payload.Length);
        }

        foreach (int pid in targetPids)
            Flush(pid);

        byte[] result = output.ToArray();
        if (result.Length != data.Length)
            throw new InvalidDataException($"DEIQ 处理后分片大小异常: {data.Length} -> {result.Length}");
        return result;
    }

    private static byte[] DecryptEs(byte[] payload, byte[] blockKey, Aes aes)
    {
        // NAL 起始码：00 00 00 01 或 00 00 01（与 iqy_deiq.py 的 NAL_START_PATTERN 一致）
        var starts = new List<int>();
        int i = 0;
        while (i + 3 < payload.Length)
        {
            if (payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 1)
            {
                starts.Add(i);
                i += 3;
                continue;
            }
            if (payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 0 && payload[i + 3] == 1)
            {
                starts.Add(i);
                i += 4;
                continue;
            }
            i++;
        }
        if (starts.Count == 0)
            return payload;

        byte[] output = (byte[])payload.Clone();
        for (int k = 0; k < starts.Count; k++)
        {
            int start = starts[k];
            int end = k + 1 < starts.Count ? starts[k + 1] : payload.Length;
            byte[] nal = new byte[end - start];
            Buffer.BlockCopy(payload, start, nal, 0, nal.Length);
            byte[] decryptedNal = DecryptNal(nal, blockKey, aes);
            Buffer.BlockCopy(decryptedNal, 0, output, start, decryptedNal.Length);
        }
        return output;
    }

    private static byte[] DecryptNal(byte[] nal, byte[] blockKey, Aes aes)
    {
        // 去掉仿真预防字节 00 00 03 -> 00 00（仅当其后字节在 00..03）
        byte[] unescaped = RemoveEmulationPrevention(nal);
        int bodyLength = unescaped.Length - 7;
        if (bodyLength <= 0)
            return nal;

        int blockCount = (bodyLength + 15) / 16;
        byte[][] keyStream = new byte[blockCount][];
        for (int counter = 1; counter <= blockCount; counter++)
        {
            byte[] row = new byte[16];
            Buffer.BlockCopy(blockKey, 0, row, 0, 12);
            row[12] = (byte)(counter >> 24);
            row[13] = (byte)(counter >> 16);
            row[14] = (byte)(counter >> 8);
            row[15] = (byte)counter;
            keyStream[counter - 1] = row;
        }

        // 显式标出“走 CTR”的块：循环首块（index % CTR_CYCLE == 0）或最后一块。
        var ctrIndexes = new List<int>();
        for (int index = 0; index < blockCount; index++)
        {
            if (index % CTR_CYCLE == 0 || index == blockCount - 1)
                ctrIndexes.Add(index);
        }

        if (ctrIndexes.Count > 0)
        {
            int total = ctrIndexes.Count * 16;
            byte[] toEncrypt = new byte[total];
            for (int c = 0; c < ctrIndexes.Count; c++)
                Buffer.BlockCopy(keyStream[ctrIndexes[c]], 0, toEncrypt, c * 16, 16);
            using var enc = aes.CreateEncryptor();
            byte[] encrypted = enc.TransformFinalBlock(toEncrypt, 0, total);
            for (int c = 0; c < ctrIndexes.Count; c++)
                Buffer.BlockCopy(encrypted, c * 16, keyStream[ctrIndexes[c]], 0, 16);
        }

        byte[] stream = new byte[blockCount * 16];
        for (int c = 0; c < blockCount; c++)
            Buffer.BlockCopy(keyStream[c], 0, stream, c * 16, 16);

        byte[] body = new byte[bodyLength];
        for (int c = 0; c < bodyLength; c++)
            body[c] = (byte)(unescaped[5 + c] ^ stream[c]);

        byte[] result = (byte[])nal.Clone();
        Buffer.BlockCopy(body, 0, result, 5, bodyLength);
        Buffer.BlockCopy(unescaped, 5 + bodyLength, result, 5 + bodyLength, 2);
        if (nal.Length > unescaped.Length)
            result[unescaped.Length] = 0;
        return result;
    }

    private static byte[] RemoveEmulationPrevention(byte[] nal)
    {
        using var ms = new MemoryStream(nal.Length);
        int i = 0;
        while (i < nal.Length)
        {
            if (i + 3 < nal.Length && nal[i] == 0 && nal[i + 1] == 0 && nal[i + 2] == 3 && nal[i + 3] <= 3)
            {
                ms.WriteByte(0);
                ms.WriteByte(0);
                i += 3; // 跳过 03
            }
            else
            {
                ms.WriteByte(nal[i]);
                i++;
            }
        }
        return ms.ToArray();
    }

    private static byte[]? FindBlockKey(byte[] data)
    {
        // 模式：|v{32 hex}|
        for (int i = 0; i + 35 <= data.Length; i++)
        {
            if (data[i] != (byte)'|' || data[i + 1] != (byte)'v')
                continue;
            int hexStart = i + 2;
            if (IsHexString(data, hexStart, 32) && data[hexStart + 32] == (byte)'|')
            {
                var key = new byte[16];
                for (int j = 0; j < 32; j += 2)
                    key[j / 2] = (byte)((HexVal(data[hexStart + j]) << 4) | HexVal(data[hexStart + j + 1]));
                return key;
            }
        }
        return null;
    }

    private static bool IsHexString(byte[] data, int start, int len)
    {
        for (int j = 0; j < len; j++)
        {
            if (!IsHex(data[start + j]))
                return false;
        }
        return true;
    }

    private static bool IsHex(byte b) =>
        (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');

    private static int HexVal(byte b)
    {
        if (b >= '0' && b <= '9') return b - '0';
        if (b >= 'a' && b <= 'f') return b - 'a' + 10;
        return b - 'A' + 10;
    }

    private class PidBuffer
    {
        public List<byte[]> Packets { get; } = new();
        public List<int> Offsets { get; } = new();
        public MemoryStream Payload { get; } = new();
    }
}
