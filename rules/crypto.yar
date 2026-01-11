/*
 * Cryptocurrency mining and related patterns
 * Detects crypto miners that may be bundled in npm packages
 */

rule CryptoMiner_Strings {
    meta:
        description = "Detects cryptocurrency mining software indicators"
        severity = "high"
        category = "cryptominer"
    strings:
        $pool1 = "stratum+tcp://" ascii nocase
        $pool2 = "stratum+ssl://" ascii nocase
        $pool3 = "pool.minergate" ascii nocase
        $pool4 = "xmrpool" ascii nocase
        $pool5 = "moneropool" ascii nocase
        $pool6 = "nanopool" ascii nocase
        $pool7 = "nicehash" ascii nocase
        $pool8 = "2miners" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_XMRig {
    meta:
        description = "Detects XMRig cryptocurrency miner"
        severity = "high"
        category = "cryptominer"
    strings:
        $xmr1 = "xmrig" ascii nocase
        $xmr2 = "randomx" ascii nocase
        $xmr3 = "cryptonight" ascii nocase
        $xmr4 = "monero" ascii nocase
        $cfg1 = "\"algo\":" ascii
        $cfg2 = "\"coin\":" ascii
        $cfg3 = "\"pools\":" ascii
    condition:
        ($xmr1 or $xmr2 or $xmr3 or $xmr4) and any of ($cfg*)
}

rule CryptoMiner_Coinhive {
    meta:
        description = "Detects Coinhive or similar browser miners"
        severity = "high"
        category = "cryptominer"
    strings:
        $ch1 = "coinhive" ascii nocase
        $ch2 = "CoinHive" ascii
        $ch3 = "coin-hive" ascii nocase
        $ch4 = "cryptoloot" ascii nocase
        $ch5 = "crypto-loot" ascii nocase
        $ch6 = "webminer" ascii nocase
        $ch7 = "deepMiner" ascii nocase
    condition:
        any of them
}

rule CryptoMiner_Wallet_Address {
    meta:
        description = "Detects cryptocurrency wallet addresses"
        severity = "medium"
        category = "cryptominer"
    strings:
        // Monero addresses start with 4
        $xmr_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/ ascii
        // Bitcoin addresses
        $btc_addr1 = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/ ascii
        $btc_addr2 = /bc1[a-zA-HJ-NP-Z0-9]{39,59}/ ascii
        // Ethereum addresses
        $eth_addr = /0x[a-fA-F0-9]{40}/ ascii
    condition:
        any of them
}

rule CryptoMiner_CPU_GPU {
    meta:
        description = "Detects mining-related CPU/GPU usage patterns"
        severity = "medium"
        category = "cryptominer"
    strings:
        $cpu1 = "cpuminer" ascii nocase
        $cpu2 = "cpu-miner" ascii nocase
        $gpu1 = "cuda" ascii nocase
        $gpu2 = "opencl" ascii nocase
        $gpu3 = "ccminer" ascii nocase
        $hash1 = "hashrate" ascii nocase
        $hash2 = "hash/s" ascii nocase
        $hash3 = "H/s" ascii
        $hash4 = "MH/s" ascii
        $hash5 = "kH/s" ascii
    condition:
        ($cpu1 or $cpu2 or $gpu1 or $gpu2 or $gpu3) and any of ($hash*)
}

