#region (c) 2022-2025 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Udap.Common.Certificates;

/// <summary>
/// Extension methods for summarizing certificate chain validation problems into human-readable strings.
/// </summary>
public static class ChainElementExtensions
{
    /// <summary>
    /// Summarizes chain problems that match the specified status flags into a single string.
    /// </summary>
    /// <param name="problems">The list of chain problems to summarize.</param>
    /// <param name="problemFlags">The status flags to filter by. Only problems matching these flags are included.</param>
    /// <returns>A summary string of matching problems, or an empty string if none match.</returns>
    public static string Summarize(this IReadOnlyList<ChainProblem> problems, ChainProblemStatus problemFlags)
    {
        var builder = new StringBuilder();

        foreach (var problem in problems)
        {
            if ((problem.Status & problemFlags) != 0)
            {
                builder.Append($"({problem.Status}) {problem.StatusInformation}");
                builder.Append(" : ");
            }
        }

        return builder.ToString();
    }

    /// <summary>
    /// Summarizes all non-<see cref="ChainProblemStatus.None"/> problems across all chain elements,
    /// including the certificate's Subject Alternative Name for each problem.
    /// </summary>
    /// <param name="chainElements">The chain elements to summarize.</param>
    /// <returns>A multi-line summary of all chain validation problems.</returns>
    public static string Summarize(this IReadOnlyList<ChainElementInfo> chainElements)
    {
        var builder = new StringBuilder();
        builder.AppendLine();

        foreach (var element in chainElements)
        {
            foreach (var problem in element.Problems)
            {
                if (problem.Status != ChainProblemStatus.None)
                {
                    builder.AppendLine($"SubAltName:: {element.Certificate.GetNameInfo(X509NameType.UrlName, false)} ({problem.Status}) {problem.StatusInformation}");
                }
            }
        }

        return builder.ToString();
    }
}
