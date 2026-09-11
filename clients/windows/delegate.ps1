param(
    [Parameter(Mandatory = $true)][string]$Request,
    [string]$Python = "python",
    [string]$WorkerPath = $env:MCP_PORTAL_WORKER
)
$ErrorActionPreference = 'Stop'
if (-not $WorkerPath) {
    $WorkerPath = 'wsl.exe -- python3 -m mcp_portal.delegate --worker'
}
& $Python -m mcp_portal.delegate --request $Request --route auto --worker-path $WorkerPath
exit $LASTEXITCODE
