The Yara rule named "Detect_Suspicious_Script," authored by "Yara DetecWiz," is designed to identify scripts engaging in reconnaissance activities. It does this by searching for specific strings within a script that are commonly associated with reconnaissance tactics. These strings are:

"whoami": A command used to identify the current user.
"Get-LocalUser": A PowerShell cmdlet that retrieves local user accounts.
"C:\\Users": A file path that might be explored for user information.
"net": A command that can be used to gather network information or manage network resources.
Additionally, it looks for:

"ipconfig": A command that displays the IP configuration for a machine, useful for identifying network settings.
"netstat": A command that displays network statistics, potentially used to find active connections.
The rule also searches for a misspelled string "Start-Slepp" (likely intended to be "Start-Sleep"), a PowerShell cmdlet that pauses a script for a set period, which might be used in scripts to evade detection or time operations.

The condition for the rule to trigger is the presence of any of these strings within a script, indicating potential reconnaissance activity. This broad condition means that the detection is relatively sensitive, as it will flag any script containing at least one of these indicators.
