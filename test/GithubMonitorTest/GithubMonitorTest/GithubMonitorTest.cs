using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.Metadata;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Ahk.GitHub.Monitor;
using Ahk.GitHub.Monitor.EventHandlers;
using Ahk.GitHub.Monitor.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using Octokit;

namespace GithubMonitorTest
{
    class NullEventDispatchService : IEventDispatchService
    {
        public Task Process(string githubEventName, string requestBody, WebhookResult webhookResult)
        {
            return Task.Delay(0);
        }
    }

    class TestHandler : IGitHubEventHandler
    {
        public async Task<EventHandlerResult> Execute(string requestBody)
        {
            return EventHandlerResult.ActionPerformed("Test");
        }
    }

    class Test2Handler : IGitHubEventHandler
    {
        public async Task<EventHandlerResult> Execute(string requestBody)
        {
            return new EventHandlerResult(requestBody);
        }
    }


    [TestClass]
    public class GithubMonitorTest
    {
        private const string AppId = "appid";
        private const string PrivateKey = "privatekey";
        private const string WebhookSecret = "webhooksecret";
        private const string OrganizationLogin = "aabbcc";
        private const long InstallationId = 9988776;
        private const long RepositoryId = 339316008;

        private readonly ILogger logger = NullLoggerFactory.Instance.CreateLogger("null logger");

        private readonly Mock<IGitHubClientFactory> githubClientFactory = new Mock<IGitHubClientFactory>();
        private readonly Mock<IGitHubClient> githubClient = new Mock<IGitHubClient>();

        public GithubMonitorTest()
        {
            githubClientFactory.Setup(x => x.CreateGitHubClient(InstallationId))
                .ReturnsAsync(githubClient.Object);
        }

        private IOptions<GitHubMonitorConfig> GetConfig(string appId = AppId, string privateKey = PrivateKey, string webhookSecret = WebhookSecret)
        {
            return Options.Create(new GitHubMonitorConfig
            {
                GitHubAppId = appId,
                GitHubAppPrivateKey = privateKey,
                GitHubWebhookSecret = webhookSecret
            });
        }

        private static string SignPayload(byte[] payload)
        {
            var hmacsha1 = new HMACSHA1(Encoding.ASCII.GetBytes(WebhookSecret));
            var binarySignature = hmacsha1.ComputeHash(payload);
            var hexString = BitConverter.ToString(binarySignature).Replace("-", string.Empty).ToLower();
            return "sha1=" + hexString;
        }

        private static void ParseRequestFile(string content, HttpRequest request, bool sign = true)
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
            var buffer = Encoding.UTF8.GetBytes(body);
            request.Body = new MemoryStream(buffer);
            if (sign)
            {
                request.Headers["X-Hub-Signature"] = SignPayload(buffer);
            }

            request.Method = headers["Request method"];
            request.ContentType = headers["content-type"];
        }

        private void SetupAhkMonitorYml(bool orgPrivateRepo = true)
        {
            var ahkMonitorPath = Path.Combine(Directory.GetCurrentDirectory(), @"ahk-monitor.yml");
            Assert.IsTrue(File.Exists(ahkMonitorPath));
            var contentBase64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(File.ReadAllText(ahkMonitorPath)));
            var contents = new List<RepositoryContent>
            {
                new RepositoryContent("", "", "", 0, ContentType.File, "", "", "", "", "", contentBase64, "",
                    "")
            };
            if (orgPrivateRepo)
            {
                githubClient
                    .Setup(x => x.Repository.Content.GetAllContents(OrganizationLogin, "ahk-monitor-config",
                        "ahk-monitor.yml")).ReturnsAsync(contents);
            }
            else
            {
                githubClient
                    .Setup(x => x.Repository.Content.GetAllContentsByRef(RepositoryId, ".github/ahk-monitor.yml",
                        It.IsAny<string>())).ReturnsAsync(contents);
            }
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
            ParseRequestFile(fileContent, request, false);

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
            ParseRequestFile(fileContent, request, false);
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
            ParseRequestFile(fileContent, request, false);

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            var messagesField = typeof(WebhookResult).GetField("Messages");
            var messages = messagesField?.GetValue(response.Value) as List<string>;
            Assert.IsNotNull(messages);
            Assert.IsTrue(messages.First().Contains("test exception"));
        }

        [TestMethod]
        public async Task EventDispatchServiceTest()
        {
            var sc = new ServiceCollection();
            sc.AddSingleton<TestHandler>();
            sc.AddSingleton<Test2Handler>();
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                    .Add<TestHandler>("invoke_test")
                    .Add<Test2Handler>("test2");
            var dispatcher = new EventDispatchService(serviceProvider, builder);

            var result1 = new WebhookResult();
            await dispatcher.Process("invoke_test", string.Empty, result1);
            var result2 = new WebhookResult();
            await dispatcher.Process("test2", "test request body", result2);

            Assert.IsTrue(result1.Messages.First().Contains("Test"));
            Assert.IsTrue(result2.Messages.First().Contains("test request body"));
        }

        [TestMethod]
        [DeploymentItem(@"resources/pr_opened.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task PrOpenedNoDuplicates()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new PullRequestOpenDuplicateHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<PullRequestOpenDuplicateHandler>(PullRequestOpenDuplicateHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"pr_opened.txt")), request);
            githubClient.Setup(x => x.PullRequest.GetAllForRepository(RepositoryId)).ReturnsAsync(new List<PullRequest>().AsReadOnly());
            githubClient.Setup(x => x.PullRequest.GetAllForRepository(RepositoryId, It.IsAny<PullRequestRequest>())).ReturnsAsync(new List<PullRequest>().AsReadOnly());
            SetupAhkMonitorYml();

            var response = (ObjectResult) await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            Assert.IsTrue(webhookResult.Messages.Any(m => m.Equals("PullRequestOpenDuplicateHandler -> no action needed: pull request open is ok, there are no other PRs")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/pr_opened.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task PrOpenedWithDuplicates()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new PullRequestOpenDuplicateHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<PullRequestOpenDuplicateHandler>(PullRequestOpenDuplicateHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"pr_opened.txt")), request);
            var prs = new List<PullRequest>()
            {
                new PullRequest(5748988117, "", "", "", "", "", "", "", 1, ItemState.Open, "", "", DateTimeOffset.Now,
                    DateTimeOffset.Now, null, null, new GitReference(), new GitReference(), new User(), new User(),
                    new List<User>().AsReadOnly(), false, true, MergeableState.Clean, null, "", 0, 0, 0, 0, 0,
                    new Milestone(), false, true, new List<User>().AsReadOnly(), new List<Team>().AsReadOnly(),
                    new List<Label>().AsReadOnly()),
                new PullRequest(5748988118, "", "", "", "", "", "", "", 2, ItemState.Open, "", "", DateTimeOffset.Now,
                    DateTimeOffset.Now, null, null, new GitReference(), new GitReference(), new User(), new User(),
                    new List<User>().AsReadOnly(), false, true, MergeableState.Clean, null, "", 0, 0, 0, 0, 0,
                    new Milestone(), false, true, new List<User>().AsReadOnly(), new List<Team>().AsReadOnly(),
                    new List<Label>().AsReadOnly())
            }.AsReadOnly();
            githubClient.Setup(x => x.PullRequest.GetAllForRepository(RepositoryId)).ReturnsAsync(prs);
            githubClient.Setup(x => x.PullRequest.GetAllForRepository(RepositoryId, It.IsAny<PullRequestRequest>())).ReturnsAsync(prs);
            githubClient.Setup(x =>
                x.Issue.Comment.Create(It.IsAny<int>(), It.IsAny<int>(), It.IsAny<string>())).Verifiable();
            SetupAhkMonitorYml(false);

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            githubClient.Verify(x => x.Issue.Comment.Create(RepositoryId, 1, "multiple PR protection warning"), Times.Never);
            githubClient.Verify(x => x.Issue.Comment.Create(RepositoryId, 2, "multiple PR protection warning"), Times.Once);
            Assert.IsTrue(webhookResult.Messages.Any(m => m.Equals("PullRequestOpenDuplicateHandler -> action performed: pull request open handled with multiple open PRs; pull request open is ok, there are no other closed PRs")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/branch_create.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task BranchCreate()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new BranchProtectionRuleHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<BranchProtectionRuleHandler>(BranchProtectionRuleHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"branch_create.txt")), request);
            githubClient.Setup(x =>
                    x.Repository.Branch.UpdateBranchProtection(RepositoryId, "master",
                        It.IsAny<BranchProtectionSettingsUpdate>()))
                .Verifiable();
            SetupAhkMonitorYml();

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            githubClient.Verify(x => x.Repository.Branch.UpdateBranchProtection(RepositoryId, "master", It.IsAny<BranchProtectionSettingsUpdate>()), Times.Once);
            Assert.IsTrue(webhookResult.Messages.Any(m => m.Equals("BranchProtectionRuleHandler -> action performed: branch protection rule applied")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/comment_delete.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task CommentDelete()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new IssueCommentEditDeleteHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<IssueCommentEditDeleteHandler>(IssueCommentEditDeleteHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"comment_delete.txt")), request);
            githubClient.Setup(x => x.Issue.Comment.Create(RepositoryId, 1, "comment protection warning")).Verifiable();
            SetupAhkMonitorYml(false);

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            githubClient.Verify(x => x.Issue.Comment.Create(RepositoryId, 1, "comment protection warning"), Times.Once);
            Assert.IsTrue(webhookResult.Messages.Any(m => m.Equals("IssueCommentEditDeleteHandler -> action performed: comment action resulting in warning")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/comment_delete_own.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task CommentDeleteOwn()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new IssueCommentEditDeleteHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<IssueCommentEditDeleteHandler>(IssueCommentEditDeleteHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"comment_delete_own.txt")), request);
            SetupAhkMonitorYml();

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            Assert.IsTrue(webhookResult.Messages.Any(m =>
                m.Equals("IssueCommentEditDeleteHandler -> no action needed: comment action deleted by abcabc allowed, referencing own comment")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/comment_edited.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task CommentEdited()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new IssueCommentEditDeleteHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<IssueCommentEditDeleteHandler>(IssueCommentEditDeleteHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"comment_edited.txt")), request);
            githubClient.Setup(x => x.Issue.Comment.Create(RepositoryId, 1, "comment protection warning")).Verifiable();
            SetupAhkMonitorYml();

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            githubClient.Verify(x => x.Issue.Comment.Create(RepositoryId, 1, "comment protection warning"), Times.Once);
            Assert.IsTrue(webhookResult.Messages.Any(m => m.Equals("IssueCommentEditDeleteHandler -> action performed: comment action resulting in warning")));
        }

        [TestMethod]
        [DeploymentItem(@"resources/comment_edited_own.txt")]
        [DeploymentItem(@"resources/ahk-monitor.yml")]
        public async Task CommentEditedOwn()
        {
            var context = new DefaultHttpContext();
            var request = context.Request;
            var sc = new ServiceCollection();
            sc.AddSingleton(sp => new IssueCommentEditDeleteHandler(githubClientFactory.Object));
            var serviceProvider = sc.BuildServiceProvider();
            var builder = new EventDispatchConfigBuilder(sc)
                .Add<IssueCommentEditDeleteHandler>(IssueCommentEditDeleteHandler.GitHubWebhookEventName);
            var dispatcher = new EventDispatchService(serviceProvider, builder);
            var function = new GitHubMonitorFunction(dispatcher, GetConfig());
            ParseRequestFile(
                await File.ReadAllTextAsync(Path.Combine(Directory.GetCurrentDirectory(), @"comment_edited_own.txt")), request);
            SetupAhkMonitorYml();

            var response = (ObjectResult)await function.Run(request, logger);

            Assert.IsNotNull(response);
            Assert.IsInstanceOfType(response, typeof(OkObjectResult));
            var webhookResult = response.Value as WebhookResult;
            Assert.IsNotNull(webhookResult);
            Assert.IsTrue(webhookResult.Messages.Any(m =>
                m.Equals("IssueCommentEditDeleteHandler -> no action needed: comment action edited by abcabc allowed, referencing own comment")));
        }
    }
}