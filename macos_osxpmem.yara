rule osxpmem
{
	meta:
		description = "OSXPMEM is a memory acquisition and analysis tool used to quickly collect RAM from a Mac system."
		reference = "https://github.com/google/rekall/releases"
		updated = "2018-10-30"
		hash = "297891f87bcf73dfcf396083c0721dd2"

	strings:
		$a1 = "osxpmem" nocase wide  ascii
		$a2 = "Adding the memory namespaces" nocase wide ascii
		$a3 = "%sMacPmem.kext" nocase wide ascii
		$a4 = "2PmemMetadata" nocase wide ascii
		$a5 = "PmemImager" nocase wide ascii
		$a6 = "rekall" nocase wide ascii

	condition:
		2 of them
}
