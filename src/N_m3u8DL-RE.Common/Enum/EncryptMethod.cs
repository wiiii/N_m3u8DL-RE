namespace N_m3u8DL_RE.Common.Enum;

public enum EncryptMethod
{
    NONE,
    AES_128,
    AES_128_ECB,
    SAMPLE_AES,
    SAMPLE_AES_CTR,
    CENC,
    CHACHA20,
    // DEIQ (爱奇艺 DRM v3) 就地解密:下载器下载后用 iqy_deiq 算法(C# 移植,
    // 见 N_m3u8DL-RE.Crypto.DeiqUtil)直接解密 TS 分片,无需外部 Python 依赖。
    DEIQ,
    // SM4 (国密 GB/T 32907-2016) 就地解密:主要用于优酷(Youku)等 SM4-CBC 的
    // HLS 流。下载器下载后用纯 C# SM4(见 N_m3u8DL-RE.Crypto.SM4Util)做
    // CBC 解密并就地写回分片,无需外部 Python 依赖。需 --custom-hls-key 与
    // --custom-hls-iv 各 16 字节。
    SM4,
    // AES_128_YK (优酷 copyrightDRM 默认) 就地解密:每个 TS 包的 PES 载荷
    // 按 PES 分组做 AES-128-ECB 解密,16 字节媒体密钥由 --custom-hls-key(HEX
    // 或 Base64)传入。算法见 N_m3u8DL-RE.Crypto.YkUtil(2026-08-30 实证:
    // 真实样本 ffprobe 全解码零错误)。
    AES_128_YK,
    // DEYK (Decrypt YouKu) 就地解密:与 AES_128_YK 同算法,密钥用 Base64
    // 形式(YOUKU.exe 同款);--custom-hls-key 解析器已支持 Base64,直接复用。
    DEYK,
    UNKNOWN
}