/*
 New Yara rule to detect Tic Tac Toe Dropper
 Supports the blog about Tic Tac Toe Malware Dropper <Blog URL to be added>
*/
rule Tic_Tac_Toe_Dropper_rule1
{
  meta:
    author = "Amey Gat <contact[@]ameygat[.]com>"
    description = "Rule to find Tic-Tac-Toe malware Dropper"
    target_entity = "file"
  strings:
    $a = {4b006f006c006b006f005f0069005f006b0072007a0079007a0079006b002e00500072006f0070006500720074006900650073002e005200650073006f0075007200630065007300}
    $b = {4b006f006c006b006f005f0069005f006b0072007a0079007a0079006b002e005200650073006f0075007200630065005800}
    $c = {4b6f6c6b6f5f695f6b727a797a796b2e50726f70657274696573}
    $d = {4b6f6c6b6f5f695f6b727a797a796b2e466f726d312e7265736f7572636573}
    $e = {4b6f6c6b6f5f695f6b727a797a796b2e41626f7574426f78312e7265736f7572636573} 

  condition:
    any of them
}