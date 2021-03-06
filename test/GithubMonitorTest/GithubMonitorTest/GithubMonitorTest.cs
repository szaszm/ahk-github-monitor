using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
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

        private readonly ILogger logger = NullLoggerFactory.Instance.CreateLogger("null logger");

        private IOptions<GitHubMonitorConfig> GetConfig(string appId = AppId, string privateKey = PrivateKey, string webhookSecret = WebhookSecret)
        {
            return Options.Create(new GitHubMonitorConfig
            {
                GitHubAppId = appId,
                GitHubAppPrivateKey = privateKey,
                GitHubWebhookSecret = webhookSecret
            });
        }

        private string SignPayload(byte[] payload)
        {
            var hmacsha1 = new HMACSHA1(Encoding.ASCII.GetBytes(WebhookSecret));
            var binarySignature = hmacsha1.ComputeHash(payload);
            var hexString = BitConverter.ToString(binarySignature).Replace("-", string.Empty).ToLower();
            return "sha1=" + hexString;
        }

        private static void ParseRequestFile(string content, HttpRequest request)
        {
            content = content.Replace("\r\n", "\n");
            var headerSeparatorIndex = content.IndexOf("\n\n", StringComparison.Ordinal);
            var headers = content.Substring(0, headerSeparatorIndex)
                .Split("\n")
                .Select(line => line.Split(':').Select(s => s.Trim()))
                .ToDictionary(line => line.First(), line => line.Last());
            foreach (var (key, value) in headers)
            {
                request.Headers[key] = value;
            }

            var body = content.Substring(headerSeparatorIndex + "\n\n".Length);
            request.ContentLength = body.Length;
            request.Body = new MemoryStream(Encoding.UTF8.GetBytes(body));

            request.Method = headers["Request method"];
            request.ContentType = headers["content-type"];
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

            var responseAppidNull = (ObjectResult) await functionAppIdNull.Run(request, logger);
            var responsePrivateKeyNull = (ObjectResult) await functionPrivateKeyNull.Run(request, logger);
            var responseWebhookSecretNull = (ObjectResult) await functionWebhookSecretNull.Run(request, logger);

            Assert.AreEqual(StatusCodes.Status500InternalServerError, responseAppidNull?.StatusCode);
            Assert.AreEqual(StatusCodes.Status500InternalServerError, responsePrivateKeyNull?.StatusCode);
            Assert.AreEqual(StatusCodes.Status500InternalServerError, responseWebhookSecretNull?.StatusCode);
        }

        [TestMethod]
        [DeploymentItem(@"resources/invalid_signature_rejected.txt")]
        public async Task InvalidSignatureRejected()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var function = new GitHubMonitorFunction(new NullEventDispatchService(), GetConfig());
            var fileContent =
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(),
                    @"invalid_signature_rejected.txt"));
            ParseRequestFile(fileContent, request);

            var response = (ObjectResult) await function.Run(request, logger);

            Assert.AreEqual(StatusCodes.Status400BadRequest, response?.StatusCode);
            var errorProperty = response?.Value.GetType().GetProperty("error");
            Assert.AreEqual("Payload signature not valid", errorProperty?.GetValue(response.Value));
        }

        [TestMethod]
        [DeploymentItem(@"resources/valid_signature_accepted.txt")]
        public async Task ValidSignatureAccepted()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var function = new GitHubMonitorFunction(new NullEventDispatchService(), GetConfig());
            var fileContent =
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(),
                    @"valid_signature_accepted.txt"));
            ParseRequestFile(fileContent, request);
            var contentBytes = new byte[request.Body.Length];
            await request.Body.ReadAsync(contentBytes, 0, contentBytes.Length);
            request.Body.Seek(0, SeekOrigin.Begin);

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.AreEqual("{}", Encoding.UTF8.GetString(contentBytes));
            Assert.AreEqual(StatusCodes.Status200OK, response?.StatusCode);
        }

        [TestMethod]
        [DeploymentItem(@"resources/valid_signature_accepted.txt")]
        public async Task ExceptionsAreLogged()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var throwingDispatcher = new Mock<IEventDispatchService>();
            throwingDispatcher.Setup(x => x.Process(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<WebhookResult>()))
                .Throws(new Exception("test exception"));
            var function = new GitHubMonitorFunction(throwingDispatcher.Object, GetConfig());
            var fileContent =
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(),
                    @"valid_signature_accepted.txt"));
            ParseRequestFile(fileContent, request);

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            var messagesField = typeof(WebhookResult).GetField("Messages");
            var messages = messagesField?.GetValue(response.Value) as List<string>;
            Assert.IsNotNull(messages);
            Assert.IsTrue(messages.First().Contains("test exception"));
        }
    }
}