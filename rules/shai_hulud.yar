rule JS_Obfuscated_ArrayRotate_ParseIntChain_Bundles
{
  meta:
    description = "Minified bundle-friendly detection: while(!![]) + parseInt(id(0xNNN)) chain + push/shift rotation; ignores a*/_* variable names and whitespace"
    author = "ChatGPT"
    date = "2026-01-09"
    severity = "high"
    category = "obfuscation"

  strings:
    // Fast anchors (cheap substring checks)
    $s_while   = "while(!![])" ascii
    $s_parse   = "parseInt(" ascii

    $s_push_s  = "['push'](" ascii
    $s_shift_s = "['shift'](" ascii
    $s_push_d  = "[\"push\"](" ascii
    $s_shift_d = "[\"shift\"](" ascii

    // parseInt( <id>(0x1234) ) where <id> starts with a or _
    // NOTE: YARA does NOT support (?: ... ) so we use ( ... )
    $rx_parse_call = /parseInt\s*\(\s*(a[0-9A-Za-z_]*|_[0-9A-Za-z_]*)\s*\(\s*0x[0-9a-fA-F]{3,6}\s*\)\s*\)/ ascii

    // arr['push'](arr['shift']()); allowing both ' and " forms
    $rx_push_shift = /(a[0-9A-Za-z_]*|_[0-9A-Za-z_]*)\s*\[\s*('push'|"push")\s*\]\s*\(\s*(a[0-9A-Za-z_]*|_[0-9A-Za-z_]*)\s*\[\s*('shift'|"shift")\s*\]\s*\(\s*\)\s*\)\s*;?/ ascii

    // Optional IIFE-ish opener (kept as a confidence booster if you want it later)
    $rx_iife = /\(\s*function\s*\(\s*(a[0-9A-Za-z_]*|_[0-9A-Za-z_]*)\s*,\s*(a[0-9A-Za-z_]*|_[0-9A-Za-z_]*)\s*\)\s*\{/ ascii

  condition:
    // keep scanning fast in node_modules bundles
    filesize < 15MB
    and $s_parse
    and $s_while
    and ( $s_push_s or $s_push_d )
    and ( $s_shift_s or $s_shift_d )
    and $rx_push_shift
    and #rx_parse_call >= 6
    and $rx_iife
}

