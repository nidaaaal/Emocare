using Emocare.Domain.Interfaces.Helper.Common;
using Microsoft.Extensions.Configuration;
    using System.Text.Json;
    using WebPush;

namespace Emocare.Shared.Helpers.Common
{
    public class PushNotificationHelper : IPushNotificationHelper
    {
        private readonly VapidDetails _vapidDetails;

        public PushNotificationHelper(IConfiguration config)
        {
            _vapidDetails = new VapidDetails(
                subject: "mailto:admin@yourdomain.com",
                publicKey: config["Vapid:PublicKey"],
                privateKey: config["Vapid:PrivateKey"]
            );
        }

        public async Task SendNotificationAsync(PushSubscription subscription, string title, string message)
        {
            var pushClient = new WebPushClient();
            var payload = JsonSerializer.Serialize(new
            {
                title,
                message,
                url = "/habits", // URL to open when clicked
                icon = "/icon-192.png"
            });

            try
            {
                await pushClient.SendNotificationAsync(subscription, payload, _vapidDetails);
            }
            catch (WebPushException ex) when (((int)ex.StatusCode) == 410) // Gone
            {
                // Subscription expired - remove from database
                throw;
            }
        }
    }
}
