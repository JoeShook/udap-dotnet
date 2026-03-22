#region (c) 2023 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   Joseph.Shook@Surescripts.com
// 
//  See LICENSE in the project root for license information.
// */
#endregion

using System.Text;

namespace Udap.Common.Extensions;

/// <summary>
/// Extension methods for generating FHIR scope string combinations.
/// </summary>
public static class ScopeExtensions
{
    /// <summary>
    /// Generates all non-empty substring combinations of the input string.
    /// Used to expand SMART v2 scope suffixes (e.g., "rs" → "r", "s", "rs").
    /// </summary>
    /// <param name="input">The string to generate combinations from.</param>
    /// <returns>A list of all non-empty character combinations.</returns>
    public static List<string> GenerateCombinations(string input)
    {
        var result = new List<string>();
        GenerateCombinationsRecursive(input.ToCharArray(), 0, new StringBuilder(), result);
        return result;
    }

    private static void GenerateCombinationsRecursive(char[] input, int index, StringBuilder current, List<string> result)
    {
        if (index == input.Length)
        {
            if (current.Length > 0)
            {
                result.Add(current.ToString());
            }

            return;
        }

        var nextChar = input[index];
        current.Append(nextChar);
        GenerateCombinationsRecursive(input, index + 1, current, result);
        current.Remove(current.Length - 1, 1);
        GenerateCombinationsRecursive(input, index + 1, current, result);
    }
}
