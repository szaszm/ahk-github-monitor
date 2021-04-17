using Octokit;
using System.Threading.Tasks;

namespace Ahk.GitHub.Monitor.Services
{
    public interface IGitHubClientFactory
    {
        Task<IGitHubClient> CreateGitHubClient(long installationId);
    }
}