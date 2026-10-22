// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Text;
using Microsoft.Mxc.Sdk;
using Microsoft.Mxc.Sdk.V1;
using Xunit;

namespace Microsoft.Mxc.Sdk.Tests.V1;

/// <summary>
/// Drives stdin through a live WSLC lifecycle exec, which needs WSL2 with the
/// WSLC runtime, a build with MxcWithWslc, alpine:latest in the daemon's image
/// store, and MXC_ENABLE_WSLC_TESTS=1.
/// </summary>
[Collection("MxcLiveHost")]
public class MxcLifecycleWslcE2ETests
{
    private static void RequireWslc()
    {
#if MXC_WITH_WSLC
        Assert.SkipUnless(
            Environment.GetEnvironmentVariable("MXC_ENABLE_WSLC_TESTS") == "1",
            "WSLC tests require MXC_ENABLE_WSLC_TESTS=1 on Windows with WSL2 and the WSLC runtime");
#else
        Assert.Skip("built without MxcWithWslc");
#endif
    }

    private sealed class StartedContainer : IDisposable
    {
        public StartedContainer()
        {
            Id = MxcLifecycle.ProvisionContainer(
                new WslcProvisionRequest { Image = "alpine:latest" }).ContainerId;
            try
            {
                MxcLifecycle.StartContainer(Id);
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public ContainerId Id { get; }

        public void Dispose()
        {
            try
            {
                MxcLifecycle.StopContainer(Id);
            }
            catch (MxcException)
            {
            }
            try
            {
                MxcLifecycle.DeprovisionContainer(Id);
            }
            catch (MxcException e)
            {
                Console.Error.WriteLine($"WARNING: WSLC deprovision failed: {e.Message}");
            }
        }
    }

    [Fact]
    public async Task SpawnInContainer_ForwardsEveryByteAndClosingStdinEndsInput()
    {
        RequireWslc();
        using var container = new StartedContainer();
        var payload = new byte[64 * 1024];
        for (var i = 0; i < payload.Length; i++)
        {
            payload[i] = (byte)(i % 256);
        }

        using var proc = MxcLifecycle.SpawnInContainer(
            container.Id,
            new ExecutionRequest("cat") { TimeoutMs = 60_000 });
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        var output = proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);
        await stdin.WriteAsync(payload, TestContext.Current.CancellationToken);
        stdin.Dispose();
        var (result, stdout, _) = await output;

        Assert.False(result.TimedOut, "cat must end once stdin is closed");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal(payload, stdout);
    }

    [Fact]
    public async Task RunInContainer_GivesACommandThatReadsStdinEndOfFile()
    {
        RequireWslc();
        using var container = new StartedContainer();

        var run = await MxcLifecycle.RunInContainerAsync(
            container.Id,
            new ExecutionRequest("sh -c 'cat; echo RUN-SAW-EOF'") { TimeoutMs = 60_000 },
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.False(run.TimedOut, "a captured run has no input to wait for");
        Assert.Equal(0, run.ExitCode);
        Assert.Equal("RUN-SAW-EOF", run.Stdout.Trim());
    }

    [Fact]
    public void SpawnInContainer_ACommandThatIgnoresStdinFinishesWhileItIsOpen()
    {
        RequireWslc();
        using var container = new StartedContainer();

        using var proc = MxcLifecycle.SpawnInContainer(
            container.Id,
            new ExecutionRequest("echo IGNORES-STDIN") { TimeoutMs = 60_000 });
        var stdin = proc.StandardInput;
        Assert.NotNull(stdin);
        using var reader = new StreamReader(proc.StandardOutput!, Encoding.UTF8);
        var stdout = reader.ReadToEnd();
        var result = proc.Wait();

        Assert.False(result.TimedOut);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("IGNORES-STDIN", stdout.Trim());
        stdin.Dispose();
    }

    [Fact]
    public async Task SpawnInContainer_WaitClosesAnUntakenStdin()
    {
        RequireWslc();
        using var container = new StartedContainer();

        using var proc = MxcLifecycle.SpawnInContainer(
            container.Id,
            new ExecutionRequest("sh -c 'cat; echo WAIT-SAW-EOF'") { TimeoutMs = 60_000 });
        var (result, stdout, _) =
            await proc.WaitForExitWithOutputAsync(TestContext.Current.CancellationToken);

        Assert.False(result.TimedOut, "waiting must close a stdin the caller never took");
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("WAIT-SAW-EOF", Encoding.UTF8.GetString(stdout).Trim());
    }
}
