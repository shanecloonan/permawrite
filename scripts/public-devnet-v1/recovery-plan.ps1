# Print a safe, explicit permanence recovery plan without mutating wallet or node state.
param(
    [string]$Rpc = "127.0.0.1:<RPC>",
    [string]$Wallet = "./wallet.json",
    [string]$CommitHash = "<COMMIT_HASH_HEX>",
    [string]$OutputPath = "./restored.bin",
    [string[]]$Peer = @(),
    [string]$DataDir = "",
    [switch]$Replace
)
$ErrorActionPreference = "Stop"

function Show-Line {
    param([string]$Text = "")
    Write-Host $Text
}

$replaceToken = if ($Replace) { " replace" } else { "" }
$peerList = if ($Peer.Count -gt 0) { ($Peer -join " ") } else { "<PEER_HTTP>" }
$supportPeer = if ($Peer.Count -gt 0) { $Peer[0] } else { "<PEER_HTTP>" }
$dataDirText = if ($DataDir) { $DataDir } else { "<REPLICA_DATA_DIR>" }

Show-Line "recovery-plan: read-only plan"
Show-Line "  rpc=$Rpc"
Show-Line "  wallet=$Wallet"
Show-Line "  commit_hash=$CommitHash"
Show-Line "  output_path=$OutputPath"
Show-Line "  replace=$([bool]$Replace)"
Show-Line ""
Show-Line "Safety first:"
Show-Line "  1. Back up the wallet file and {wallet_stem}.upload-artifacts/ before any repair."
Show-Line "  2. Run a support bundle before mutating local artifacts:"
Show-Line "     powershell -File scripts/public-devnet-v1/support-bundle.ps1 -Rpc $Rpc -Wallet $Wallet -CommitHash $CommitHash -Peer $supportPeer -DataDir $dataDirText"
Show-Line "  3. Use replace only when the existing artifact/output file may be overwritten."
Show-Line ""
Show-Line "HTTP peer restore (rebuild artifact + write restored payload):"
Show-Line "  mfn-cli --rpc $Rpc --wallet $Wallet uploads fetch-http $CommitHash $OutputPath $peerList$replaceToken --json"
Show-Line ""
Show-Line "P2P inbox restore (inspect, assemble artifact, then export payload):"
Show-Line "  mfn-cli --rpc $Rpc operator inbox-status $CommitHash $dataDirText --json"
Show-Line "  mfn-cli --rpc $Rpc --wallet $Wallet operator assemble-inbox $CommitHash $dataDirText$replaceToken --json"
Show-Line "  mfn-cli --wallet $Wallet uploads retrieve $CommitHash $OutputPath$replaceToken"
Show-Line ""
Show-Line "After restore:"
Show-Line "  Compare the restored payload hash with the uploader or known-good peer before proving."
Show-Line "  mfn-cli --rpc $Rpc --wallet $Wallet operator prove $CommitHash --json"
Show-Line "  mfn-cli --rpc $Rpc uploads list --include-claims --json"
