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

public static class ChainElementExtensions
{
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
