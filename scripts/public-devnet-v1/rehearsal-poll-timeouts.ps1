# Shared GHA/local poll ceilings for start-all + participant-rehearsal-smoke (M2.5.43).
$script:MFN_POLL_HUB_MAX = if ($env:MFN_POLL_HUB_MAX) { [int]$env:MFN_POLL_HUB_MAX } elseif ($env:GITHUB_ACTIONS) { 900 } else { 60 }
$script:MFN_POLL_VOTER_P2P_MAX = if ($env:MFN_POLL_VOTER_P2P_MAX) { [int]$env:MFN_POLL_VOTER_P2P_MAX } elseif ($env:GITHUB_ACTIONS) { 900 } else { 60 }
$script:MFN_POLL_VOTER_DIAL_MAX = if ($env:MFN_POLL_VOTER_DIAL_MAX) { [int]$env:MFN_POLL_VOTER_DIAL_MAX } elseif ($env:GITHUB_ACTIONS) { 900 } else { 120 }
$script:MFN_POLL_OBSERVER_MAX = if ($env:MFN_POLL_OBSERVER_MAX) { [int]$env:MFN_POLL_OBSERVER_MAX } elseif ($env:GITHUB_ACTIONS) { 900 } else { 60 }
$script:MFN_MESH_HEALTH_TIMEOUT = if ($env:MFN_MESH_HEALTH_TIMEOUT) { [int]$env:MFN_MESH_HEALTH_TIMEOUT } elseif ($env:GITHUB_ACTIONS) { 900 } else { 420 }
$script:MFN_MESH_HEALTH_POST_START_TIMEOUT = if ($env:MFN_MESH_HEALTH_POST_START_TIMEOUT) { [int]$env:MFN_MESH_HEALTH_POST_START_TIMEOUT } elseif ($env:GITHUB_ACTIONS) { 120 } else { 420 }
$script:MFN_HUB_LIVENESS_WAIT = if ($env:MFN_HUB_LIVENESS_WAIT) { [int]$env:MFN_HUB_LIVENESS_WAIT } elseif ($env:GITHUB_ACTIONS) { 900 } else { 120 }
$script:MFN_HUB_LIVENESS_MIN = if ($env:MFN_HUB_LIVENESS_MIN) { [int]$env:MFN_HUB_LIVENESS_MIN } elseif ($env:GITHUB_ACTIONS) { 2 } else { 1 }
