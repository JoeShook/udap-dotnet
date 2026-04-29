#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

namespace Sigil.UI.Services;

public class TimeDisplayService
{
    public bool UseLocalTime { get; private set; }

    public event Action? OnChanged;

    public void SetUseLocalTime(bool value)
    {
        if (UseLocalTime == value) return;
        UseLocalTime = value;
        OnChanged?.Invoke();
    }

    public string Format(DateTime dt, string format = "yyyy-MM-dd HH:mm:ss")
    {
        var adjusted = UseLocalTime ? dt.ToLocalTime() : dt;
        var suffix = UseLocalTime ? " Local" : " UTC";
        return adjusted.ToString(format) + suffix;
    }

    public string FormatShort(DateTime dt)
    {
        var adjusted = UseLocalTime ? dt.ToLocalTime() : dt;
        return adjusted.ToString("yyyy-MM-dd");
    }

    public string FormatMedium(DateTime dt)
    {
        var adjusted = UseLocalTime ? dt.ToLocalTime() : dt;
        return adjusted.ToString("yyyy-MM-dd HH:mm");
    }

    public string Label => UseLocalTime ? "Local" : "UTC";
}
