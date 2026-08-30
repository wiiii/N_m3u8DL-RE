using N_m3u8DL_RE.Common.Entity;
using N_m3u8DL_RE.Common.Enum;
using N_m3u8DL_RE.Common.Log;
using N_m3u8DL_RE.Config;
using N_m3u8DL_RE.Crypto;
using N_m3u8DL_RE.Entity;
using N_m3u8DL_RE.Util;
using Spectre.Console;

namespace N_m3u8DL_RE.Downloader;

/// <summary>
/// 简单下载器
/// </summary>
internal class SimpleDownloader : IDownloader
{
    DownloaderConfig DownloaderConfig;

    public SimpleDownloader(DownloaderConfig config)
    {
        DownloaderConfig = config;
    }

    public async Task<DownloadResult?> DownloadSegmentAsync(MediaSegment segment, string savePath, SpeedContainer speedContainer, Dictionary<string, string>? headers = null)
    {
        var url = segment.Url;
        var (des, dResult) = await DownClipAsync(url, savePath, speedContainer, segment.StartRange, segment.StopRange, headers, DownloaderConfig.MyOptions.DownloadRetryCount);
        if (dResult is { Success: true } && dResult.ActualFilePath != des)
        {
            switch (segment.EncryptInfo.Method)
            {
                case EncryptMethod.AES_128:
                {
                    var key = segment.EncryptInfo.Key;
                    var iv = segment.EncryptInfo.IV;
                    AESUtil.AES128Decrypt(dResult.ActualFilePath, key!, iv!);
                    break;
                }
                case EncryptMethod.AES_128_ECB:
                {
                    var key = segment.EncryptInfo.Key;
                    var iv = segment.EncryptInfo.IV;
                    AESUtil.AES128Decrypt(dResult.ActualFilePath, key!, iv!, System.Security.Cryptography.CipherMode.ECB);
                    break;
                }
                case EncryptMethod.CHACHA20:
                {
                    var key = segment.EncryptInfo.Key;
                    var nonce = segment.EncryptInfo.IV;

                    var fileBytes = File.ReadAllBytes(dResult.ActualFilePath);
                    var decrypted = ChaCha20Util.DecryptPer1024Bytes(fileBytes, key!, nonce!);
                    await File.WriteAllBytesAsync(dResult.ActualFilePath, decrypted);
                    break;
                }
                case EncryptMethod.SAMPLE_AES_CTR:
                    // throw new NotSupportedException("SAMPLE-AES-CTR");
                    break;
                case EncryptMethod.DEIQ:
                {
                    var key = segment.EncryptInfo.Key;
                    if (key == null || key.Length != 16)
                        throw new Exception("DEIQ 解密需要提供 16 字节的 --custom-hls-key（HEX 或 Base64）");
                    var fileBytes = File.ReadAllBytes(dResult.ActualFilePath);
                    var decrypted = DeiqUtil.DecryptIqyTs(fileBytes, key);
                    await File.WriteAllBytesAsync(dResult.ActualFilePath, decrypted);
                    // 每个分片一条，改为仅写日志文件，避免逐分片刷屏（且裸 Console.WriteLine 会被进度条渲染冲掉，在终端上显示为空行）
                    Logger.Extra("DEIQ 分片已就地解密");
                    break;
                }
                case EncryptMethod.SM4:
                {
                    var key = segment.EncryptInfo.Key;
                    var iv = segment.EncryptInfo.IV;
                    if (key == null || key.Length != 16)
                        throw new Exception("SM4 解密需要提供 16 字节的 --custom-hls-key（HEX 或 Base64）");
                    if (iv == null || iv.Length != 16)
                        throw new Exception("SM4-CBC 解密需要提供 16 字节的 --custom-hls-iv（HEX 或 Base64）");
                    var fileBytes = File.ReadAllBytes(dResult.ActualFilePath);
                    var decrypted = SM4Util.DecryptCbc(fileBytes, key, iv);
                    await File.WriteAllBytesAsync(dResult.ActualFilePath, decrypted);
                    // 同上：仅写日志文件，避免逐分片刷屏
                    Logger.Extra("SM4 分片已就地解密");
                    break;
                }
                case EncryptMethod.AES_128_YK:
                {
                    var key = segment.EncryptInfo.Key;
                    if (key == null || key.Length != 16)
                        throw new Exception("AES_128_YK 解密需要提供 16 字节的 --custom-hls-key（HEX 形式 32 字符）");
                    var fileBytes = File.ReadAllBytes(dResult.ActualFilePath);
                    var decrypted = YkUtil.DecryptYkTs(fileBytes, key);
                    await File.WriteAllBytesAsync(dResult.ActualFilePath, decrypted);
                    Logger.Extra("AES_128_YK 分片已就地解密");
                    break;
                }
                case EncryptMethod.DEYK:
                {
                    // DEYK 与 AES_128_YK 同算法，密钥形式为 Base64。
                    // --custom-hls-key 解析器已支持 Base64，会拿到 16 字节。
                    var key = segment.EncryptInfo.Key;
                    if (key == null || key.Length != 16)
                        throw new Exception("DEYK 解密需要提供 16 字节的 --custom-hls-key（Base64 形式）");
                    var fileBytes = File.ReadAllBytes(dResult.ActualFilePath);
                    var decrypted = YkUtil.DecryptYkTs(fileBytes, key);
                    await File.WriteAllBytesAsync(dResult.ActualFilePath, decrypted);
                    Logger.Extra("DEYK 分片已就地解密");
                    break;
                }
            }

            // Image头处理
            if (dResult.ImageHeader)
            {
                await ImageHeaderUtil.ProcessAsync(dResult.ActualFilePath);
            }
            // Gzip解压
            if (dResult.GzipHeader)
            {
                await OtherUtil.DeGzipFileAsync(dResult.ActualFilePath);
            }

            // 处理完成后改名
            File.Move(dResult.ActualFilePath, des);
            dResult.ActualFilePath = des;
        }
        return dResult;
    }

    private async Task<(string des, DownloadResult? dResult)> DownClipAsync(string url, string path, SpeedContainer speedContainer, long? fromPosition, long? toPosition, Dictionary<string, string>? headers = null, int retryCount = 3)
    {
        CancellationTokenSource? cancellationTokenSource = null;
        retry:
        try
        {
            cancellationTokenSource = new();
            var des = Path.ChangeExtension(path, null);

            // 已下载跳过
            if (File.Exists(des))
            {
                speedContainer.Add(new FileInfo(des).Length);
                return (des, new DownloadResult() { ActualContentLength = 0, ActualFilePath = des });
            }

            // 已解密跳过
            var dec = Path.Combine(Path.GetDirectoryName(des)!, Path.GetFileNameWithoutExtension(des) + "_dec" + Path.GetExtension(des));
            if (File.Exists(dec))
            {
                speedContainer.Add(new FileInfo(dec).Length);
                return (dec, new DownloadResult() { ActualContentLength = 0, ActualFilePath = dec });
            }

            // 另起线程进行监控
            var cts = cancellationTokenSource;
            using var watcher = Task.Factory.StartNew(async () =>
            {
                while (true)
                {
                    if (cts.IsCancellationRequested) break;
                    if (speedContainer.ShouldStop)
                    {
                        cts.Cancel();
                        Logger.DebugMarkUp("Cancel...");
                        break;
                    }
                    await Task.Delay(500);
                }
            });

            // 调用下载
            var result = await DownloadUtil.DownloadToFileAsync(url, path, speedContainer, cancellationTokenSource, headers, fromPosition, toPosition);
            return (des, result);

            throw new Exception("please retry");
        }
        catch (Exception ex)
        {
            Logger.DebugMarkUp($"[grey]{ex.Message.EscapeMarkup()} retryCount: {retryCount}[/]");
            Logger.Debug(url + " " + ex);
            Logger.Extra($"Ah oh!{Environment.NewLine}RetryCount => {retryCount}{Environment.NewLine}Exception  => {ex.Message}{Environment.NewLine}Url        => {url}");
            if (retryCount-- > 0)
            {
                await Task.Delay(1000);
                goto retry;
            }
            else
            {
                Logger.Extra($"The retry attempts have been exhausted and the download of this segment has failed.{Environment.NewLine}Exception  => {ex.Message}{Environment.NewLine}Url        => {url}");
                Logger.WarnMarkUp($"[grey]{ex.Message.EscapeMarkup()}[/]");
            }
            // throw new Exception("download failed", ex);
            return default;
        }
        finally
        {
            if (cancellationTokenSource != null)
            {
                // 调用后销毁
                cancellationTokenSource.Dispose();
                cancellationTokenSource = null;
            }
        }
    }
}