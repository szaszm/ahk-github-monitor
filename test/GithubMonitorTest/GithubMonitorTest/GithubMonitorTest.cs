using System.Threading.Tasks;
using Ahk.GitHub.Monitor;
using Ahk.GitHub.Monitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;

namespace GithubMonitorTest
{
    class NullEventDispatchService : IEventDispatchService
    {
        public Task Process(string githubEventName, string requestBody, WebhookResult webhookResult)
        {
            return Task.Delay(0);
        }
    }

    [TestClass]
    public class GithubMonitorTest
    {
        private const string AppId = "appid";
        private const string PrivateKey = "privatekey";
        private const string WebhookSecret = "webhooksecret";

        private ILogger logger = NullLoggerFactory.Instance.CreateLogger("null logger");

        private IOptions<GitHubMonitorConfig> GetConfig(string appId = AppId, string privateKey = PrivateKey, string webhookSecret = WebhookSecret)
        {
            return Options.Create<GitHubMonitorConfig>(new GitHubMonitorConfig()
            {
                GitHubAppId = appId,
                GitHubAppPrivateKey = privateKey,
                GitHubWebhookSecret = webhookSecret
            });
        }

        [TestMethod]
        public async Task EmptyRequestResultsInHttp400()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var function = new GitHubMonitorFunction(new NullEventDispatchService(), GetConfig());

            ObjectResult response = (ObjectResult)await function.Run(request, logger);

            Assert.AreEqual(StatusCodes.Status400BadRequest, response?.StatusCode);
        }

        [TestMethod]
        public async Task MissingParametersRejectedWithHttp500()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var dispatcher = new NullEventDispatchService();
            var functionAppIdNull = new GitHubMonitorFunction(dispatcher, GetConfig(null));
            var functionPrivateKeyNull = new GitHubMonitorFunction(dispatcher, GetConfig(AppId, null));
            var functionWebhookSecretNull = new GitHubMonitorFunction(dispatcher, GetConfig(AppId, PrivateKey, null));

            ObjectResult responseAppidNull = (ObjectResult) await functionAppIdNull.Run(request, logger);
            ObjectResult responsePrivateKeyNull = (ObjectResult) await functionPrivateKeyNull.Run(request, logger);
            ObjectResult responseWebhookSecretNull =
                (ObjectResult) await functionWebhookSecretNull.Run(request, logger);

            Assert.AreEqual(StatusCodes.Status500InternalServerError, responseAppidNull?.StatusCode);
            Assert.AreEqual(StatusCodes.Status500InternalServerError, responsePrivateKeyNull?.StatusCode);
            Assert.AreEqual(StatusCodes.Status500InternalServerError, responseWebhookSecretNull?.StatusCode);
        }
    }
}
