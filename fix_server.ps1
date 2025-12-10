$file = "c:/Users/will/dilithion/src/rpc/server.cpp"
$content = Get-Content $file -Raw
$newContent = $content -replace '#include <chrono>', @"
#include <chrono>
#include <thread>  // BUG #76 FIX: For std::this_thread::sleep_for
#include <crypto/randomx_hash.h>  // BUG #76 FIX: For randomx_is_mining_mode_ready()
"@
Set-Content -Path $file -Value $newContent -NoNewline
Write-Host "Done"
