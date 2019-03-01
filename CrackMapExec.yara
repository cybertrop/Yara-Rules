rule CrackMapExec

{
   meta:
       description = "CrackMapExec is a pen-testing tool predominantly used for post-exploitation and credential harvesting"
       website =  "https://github.com/byt3bl33d3r"

strings:
       $a1 = "CrackMapExec" nocase wide ascii
       $a2 = "cmedb.pyUT" nocase wide ascii
       // This is the repo in which CME lives (along with many other pen-testing tools)
       $b = "byt3bl33d3r"

       // $c is the hexdump offset of the zipped version of the tool
       $c1 = { 61 63 6b 4d 61 70 45 78 65 63 2d 6d 61 73 74 65 }

condition:
       any of them
}
