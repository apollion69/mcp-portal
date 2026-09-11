# Parse only. Never invoke the supplied command or expand expressions/variables.
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$sourceText = [Console]::In.ReadToEnd()
$parseTokens = $null
$parseErrors = $null
$syntaxTree = [System.Management.Automation.Language.Parser]::ParseInput($sourceText, [ref]$parseTokens, [ref]$parseErrors)
$foundPaths = [System.Collections.Generic.List[string]]::new()
if ($parseErrors.Count -eq 0) {
    $commands = $syntaxTree.FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($commandNode in $commands) {
        $name = $commandNode.GetCommandName()
        if ($name -notin @('Get-Content', 'gc', 'cat', 'type', 'more')) { continue }
        if ($commandNode.Redirections.Count -gt 0) { continue }
        if ($commandNode.Parent -is [System.Management.Automation.Language.PipelineAst] -and $commandNode.Parent.PipelineElements.Count -gt 1) { continue }
        $candidatePaths = [System.Collections.Generic.List[string]]::new()
        $supported = $true
        $skipEncodingValue = $false
        foreach ($element in $commandNode.CommandElements | Select-Object -Skip 1) {
            if ($skipEncodingValue) {
                $skipEncodingValue = $false
                if ($element -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { $supported = $false; break }
                continue
            }
            if ($element -is [System.Management.Automation.Language.CommandParameterAst]) {
                if ($element.ParameterName -notin @('Path', 'LiteralPath', 'Raw', 'Encoding')) { $supported = $false; break }
                if ($element.ParameterName -eq 'Encoding' -and $null -eq $element.Argument) { $skipEncodingValue = $true }
            } elseif ($element -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                $candidatePaths.Add($element.Value)
            } elseif ($element -is [System.Management.Automation.Language.ArrayLiteralAst]) {
                foreach ($arrayElement in $element.Elements) {
                    if ($arrayElement -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                        $candidatePaths.Add($arrayElement.Value)
                    } else { $supported = $false; break }
                }
            } else { $supported = $false; break }
        }
        if ($supported) { foreach ($candidatePath in $candidatePaths) { $foundPaths.Add($candidatePath) } }
    }
}
ConvertTo-Json -InputObject @($foundPaths.ToArray()) -Compress
