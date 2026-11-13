using System.Buffers.Text;
using System.Diagnostics.Metrics;
using GoldfishSend.Core.Crypto;
using GoldfishSend.Core.Net;
using GoldfishSend.Core.Options;
using GoldfishSend.Infrastructure.Delivery;
using GoldfishSend.Infrastructure.MySql;
using GoldfishSend.Infrastructure.Push;
using GoldfishSend.Infrastructure.Redis;
using GoldfishSend.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using MySqlConnector;
using StackExchange.Redis;

namespace GoldfishSend.Infrastructure;

public static class ServiceCollectionExtensions {
    public const string MeterName = "GoldfishSend";

    public static IServiceCollection AddGoldfish(
        this IServiceCollection services, GoldfishOptions options, string mySqlConnectionString, string redisConfiguration,
        string? ephemeralRedisConfiguration = null) {
        var keys = DecodeKeys(options.Keys);

        services.AddSingleton(options);
        services.AddSingleton(new Meter(MeterName));

        services.AddSingleton(_ => new MySqlDataSourceBuilder(mySqlConnectionString).Build());
        services.AddSingleton<IConnectionMultiplexer>(_ => Connect(redisConfiguration));
        services.AddSingleton(sp => string.IsNullOrWhiteSpace(ephemeralRedisConfiguration)
            ? new EphemeralRedis(sp.GetRequiredService<IConnectionMultiplexer>(), isSeparate: false)
            : new EphemeralRedis(Connect(ephemeralRedisConfiguration), isSeparate: true));

        services.AddSingleton<Db>();
        services.AddSingleton<Migrator>();
        services.AddSingleton<MailboxRepository>();
        services.AddSingleton<PendingMessageRepository>();
        services.AddSingleton(sp => ActivatorUtilities.CreateInstance<EpochKeyring>(sp, keys.EpochKek));

        services.AddSingleton(new MailboxCrypto(keys.Pepper, keys.SealSalt));
        services.AddSingleton(new VapidSigner(keys.VapidPrivateKey, options.Keys.VapidSubject));
        services.AddSingleton(new IpRangeFilter(options.Push.ExtraBlockedRanges, options.Push.DangerouslyAllowInsecureLoopback));
        services.AddSingleton(sp => new EndpointValidator(options.Push, sp.GetRequiredService<IpRangeFilter>()));
        services.AddSingleton<HostGuards>();
        services.AddSingleton<PushClient>();

        services.AddSingleton<ClusterSecret>();
        services.AddSingleton<RateLimiter>();
        services.AddSingleton<IdempotencyStore>();
        services.AddSingleton<MailboxLeases>();
        services.AddSingleton<HeldQuota>();
        services.AddSingleton<PowService>();
        services.AddSingleton<EphemeralStore>();
        services.AddSingleton<MessageQueue>();
        services.AddSingleton<DeliverySignal>();
        services.AddSingleton<DeliveryService>();

        services.AddSingleton<MailboxService>();
        services.AddSingleton<MessageService>();
        services.AddSingleton<InviteService>();

        // Every role prunes its own caches (host guards, epoch keys).
        services.AddHostedService<CachePruner>();
        if (options.HasRole("worker")) {
            services.AddHostedService<StreamDeliveryWorker>();
            services.AddHostedService<RetryWorker>();
            services.AddHostedService<MaintenanceWorker>();
        }
        return services;
    }

    private static ConnectionMultiplexer Connect(string configuration) {
        var config = ConfigurationOptions.Parse(configuration);
        config.AbortOnConnectFail = false;
        config.ClientName = "goldfish";
        // Keep keys (which can carry mailbox-derived names) and server details out of exception messages and logs.
        config.IncludeDetailInExceptions = false;
        config.IncludePerformanceCountersInExceptions = false;
        return ConnectionMultiplexer.Connect(config);
    }

    public sealed record DecodedKeys(byte[] Pepper, byte[] SealSalt, byte[] EpochKek, byte[] VapidPrivateKey);

    public static DecodedKeys DecodeKeys(KeyOptions keys) {
        return new DecodedKeys(
            Decode(keys.Pepper, nameof(keys.Pepper)),
            Decode(keys.SealSalt, nameof(keys.SealSalt)),
            Decode(keys.EpochKek, nameof(keys.EpochKek)),
            Decode(keys.VapidPrivateKey, nameof(keys.VapidPrivateKey)));
    }

    private static byte[] Decode(string value, string name) {
        try {
            var bytes = Base64Url.DecodeFromChars(value.Trim());
            if (bytes.Length == 32) {
                return bytes;
            }
        } catch (FormatException) {
            // Fall through to the error below.
        }
        throw new InvalidOperationException(
            $"Goldfish:Keys:{name} must be 32 bytes of base64url. Generate a full key set with: GoldfishSend.Api keygen");
    }
}
