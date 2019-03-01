rule fake_flash_adload_osxSchlayer
{
  meta:
    Desciption = "2nd Stage Dropper of AdLoad/OSX.Schlayer Malware"
    updated = "2019-02-05"
    hash = "833e43e3165663bae3d5b182b07d4a71"
  strings:
    $a1 = "Nzg8HHTktFRc1" nocase wide ascii
    $b1 = "./PTk9DQM9UVgGE" nocase wide ascii
    $c1 = "/usr/bin/hdiutil"
    $c2 = "-plist"
    $c3 = "-noautoopen"
    $c4 = "-noverify"
    $c5 = "-nobrowse"
    $c6 = "mount-point"
    $c7 = "/usr/bin/open"
    $c8 = "detach"
    $re1 = "(=([^&#]*)|&|#|$))"
  condition:
    $a1 or $b1 or all of ($c*) or $re1
}
