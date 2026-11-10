/*
    Cobalt Strike YARA Rule Pack — single entry point.

    yara index.yar <target>
    yarac index.yar compiled.yarc && yara -C compiled.yarc <target>
*/

include "rules/cs_shellcode_stagers.yar"
include "rules/cs_reflective_loader.yar"
include "rules/cs_beacon_config.yar"
include "rules/cs_named_pipes.yar"
include "rules/cs_powershell_loaders.yar"
include "rules/cs_sleep_mask.yar"
include "rules/cs_watermarks.yar"
