using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Text;
using System.Threading.Tasks;
using Ahk.GitHub.Monitor.Services;
using Octokit;

namespace Ahk.GitHub.Monitor.EventHandlers
{
    public class PullRequestCommentCommandHandler : RepositoryEventBase<IssueCommentPayload>
    {
        public const string GitHubWebhookEventName = "issue_comment";

        struct CommandHandler
        {
            public delegate Task<EventHandlerResult> ExecuteFunc(string commentContents, IssueCommentPayload payload);

            public delegate Task<bool> PermissionCheckFunc(IssueCommentPayload payload);

            public PermissionCheckFunc checkPermission;
            public ExecuteFunc execute;

            public CommandHandler(PermissionCheckFunc checkPermission, ExecuteFunc execute)
            {
                this.checkPermission = checkPermission;
                this.execute = execute;
            }
        }

        private readonly IDictionary<string, CommandHandler> commands;

        public PullRequestCommentCommandHandler(IGitHubClientFactory gitHubClientFactory) : base(gitHubClientFactory)
        {
            commands = new Dictionary<string, CommandHandler>()
            {
                {"ok", new CommandHandler(OkCommandPermissionCheck, OkCommandExecute)}
            }.ToImmutableDictionary();
        }

        private static Task<bool> OkCommandPermissionCheck(IssueCommentPayload payload)
        {
            return Task.FromResult(payload.Comment.AuthorAssociation == AuthorAssociation.Collaborator);
        }

        private async Task<EventHandlerResult> OkCommandExecute(string commentContents, IssueCommentPayload payload)
        {
            var merge = new MergePullRequest();
            merge.CommitTitle = $"merged PR via +ok: #{payload.Issue.Number} {payload.Issue.Title}";
            var result = await GitHubClient.PullRequest.Merge(payload.Repository.Id, payload.Issue.Number, merge);
            return result.Merged
                ? EventHandlerResult.ActionPerformed(
                    $"merged pull request #{payload.Issue.Number} {payload.Issue.Title}")
                : EventHandlerResult.PayloadError(
                    $"failed to merge pull request ${payload.Issue.Number} {payload.Issue.Title}");
        }

        protected override async Task<EventHandlerResult> execute(IssueCommentPayload webhookPayload, RepositorySettings repoSettings)
        {
            if (webhookPayload.Issue == null)
                return EventHandlerResult.PayloadError("no issue information in webhook payload");

            if (repoSettings.PullRequestCommentCommand == null || !repoSettings.PullRequestCommentCommand.Enabled)
                return EventHandlerResult.Disabled();

            if (!webhookPayload.Action.Equals("created", StringComparison.OrdinalIgnoreCase))
                return EventHandlerResult.EventNotOfInterest(webhookPayload.Action);

            var contents = webhookPayload.Comment.Body;
            if (!contents.StartsWith('+'))
                return EventHandlerResult.NoActionNeeded("comment is not a command");

            var endOfWord = contents.IndexOf(' ');
            var potentialCommand = endOfWord >= 0
                ? contents.Substring(1, contents.IndexOf(' ') - 1)
                : contents.Substring(1);

            if (!commands.ContainsKey(potentialCommand))
                return EventHandlerResult.NoActionNeeded($"invalid command: +{potentialCommand}");

            if (!await commands[potentialCommand].checkPermission(webhookPayload))
                return EventHandlerResult.PayloadError($"{webhookPayload.Comment.User.Login} is not allowed to execute the command: {contents}");

            return await commands[potentialCommand].execute(contents, webhookPayload);
        }
    }
}
