# Yara Rules

YARA rules are pattern-matching signatures used to hunt malware or classify files based on textual, binary, or structural indicators. A rule names the threat, defines one or more string/byte patterns (with wildcards, regex, hex), and sets conditions describing how those patterns must appear to trigger a match. Malware analysts organize these rules into datasets and run the YARA engine across files, memory dumps, or network captures to flag samples that match known behaviors or traits.

<https://github.com/Neo23x0/signature-base/blob/master/yara/expl_outlook_cve_2024_21413.yar>
