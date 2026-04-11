#region (c) 2026 Joseph Shook. All rights reserved.
// /*
//  Authors:
//     Joseph Shook   JoeShook@Gmail.com
//                    Joseph.Shook@Surescripts.com
//
//  See LICENSE in the project root for license information.
// */
#endregion

using Microsoft.FluentUI.AspNetCore.Components;
using Sigil.UI.Components.Shared;

namespace Sigil.UI.Services;

public class CopyableToastContent
{
    public string Message { get; set; } = string.Empty;
}

public static class ToastExtensions
{
    public static void ShowCopyableSuccess(this IToastService toastService, string message, int timeoutMs = 10000)
    {
        toastService.ShowToast<CopyableToast, CopyableToastContent>(new ToastParameters<CopyableToastContent>
        {
            Intent = ToastIntent.Success,
            Title = "Success",
            Timeout = timeoutMs,
            Content = new CopyableToastContent { Message = message },
        });
    }

    public static void ShowCopyableError(this IToastService toastService, string message, int timeoutMs = 15000)
    {
        toastService.ShowToast<CopyableToast, CopyableToastContent>(new ToastParameters<CopyableToastContent>
        {
            Intent = ToastIntent.Error,
            Title = "Error",
            Timeout = timeoutMs,
            Content = new CopyableToastContent { Message = message },
        });
    }

    public static void ShowCopyableWarning(this IToastService toastService, string message, int timeoutMs = 10000)
    {
        toastService.ShowToast<CopyableToast, CopyableToastContent>(new ToastParameters<CopyableToastContent>
        {
            Intent = ToastIntent.Warning,
            Title = "Warning",
            Timeout = timeoutMs,
            Content = new CopyableToastContent { Message = message },
        });
    }
}
